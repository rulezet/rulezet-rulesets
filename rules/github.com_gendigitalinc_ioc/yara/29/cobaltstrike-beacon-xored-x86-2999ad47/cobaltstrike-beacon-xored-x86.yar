rule cobaltstrike_beacon_xored_x86
{
	meta:
		author = "Gen Threat Labs"
		source = "https://github.com/gendigitalinc/ioc"
	strings:
		                $h01 = { FC E8??000000 [0-32] EB27 ?? 8B?? 83??04 8B?? 31?? 83??04 ?? 8B?? 31?? 89?? 31?? 83??04 83??04 31?? 39?? 7402 EBEA ?? FF?? E8D4FFFFFF }
                $h02 = { FC E8??000000 [0-32] EB2B ?? 8B??00 83C504 8B??00 31?? 83C504 55 8B??00 31?? 89??00 31?? 83C504 83??04 31?? 39?? 7402 EBE8 ?? FF?? E8D0FFFFFF }
		        $h11 = { 7402 EB(E8|EA) ?? FF?? E8(D0|D4)FFFFFF }
	condition:
        any of ($h0*) and (
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x4D5AE800 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x904D5AE8 or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90904D5A or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x9090904D or
            uint32be(@h11+12) ^ uint32be(@h11+20) == 0x90909090
        )
}