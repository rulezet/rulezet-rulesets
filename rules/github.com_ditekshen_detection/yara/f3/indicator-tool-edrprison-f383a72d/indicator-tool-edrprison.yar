rule INDICATOR_TOOL_EDRPrison {
    meta:
        author = "ditekshen"
        description = "Detects EDRPrison"
    strings:
        $s1 = "Block:" wide
        $s2 = "PacketLen:" wide
        $s3 = "DoWorkPacket_Step" ascii
        $s4 = "DoWorkAsyncNETWORK" ascii
        $s5 = "BlockMessage" ascii
        $s6 = "GetRmAddrPortNetwork" ascii
    condition: 
        uint16(0) == 0x5a4d and 5 of them
}