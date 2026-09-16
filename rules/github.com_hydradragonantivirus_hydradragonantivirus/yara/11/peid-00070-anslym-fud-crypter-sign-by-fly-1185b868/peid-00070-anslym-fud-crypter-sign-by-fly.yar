rule PEiD_00070_Anslym_FUD_Crypter___Sign_by_fly_
{
    meta:
        description = "[Anslym FUD Crypter ! Sign by fly]"
        ep_only = "true"
    strings:
        $a = {55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A}
    condition:
        $a
}