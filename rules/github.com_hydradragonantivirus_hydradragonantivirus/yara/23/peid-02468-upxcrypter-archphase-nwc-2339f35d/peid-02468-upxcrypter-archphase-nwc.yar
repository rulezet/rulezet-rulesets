rule PEiD_02468_UPXcrypter____archphase_NWC_
{
    meta:
        description = "[UPXcrypter -> archphase/NWC]"
        ep_only = "true"
    strings:
        $a = {BF ?? ?? ?? 00 81 FF ?? ?? ?? 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 ?? ?? 00 FF E3 BE ?? ?? ?? 00 FF E6 00 00 00 00}
    condition:
        $a
}