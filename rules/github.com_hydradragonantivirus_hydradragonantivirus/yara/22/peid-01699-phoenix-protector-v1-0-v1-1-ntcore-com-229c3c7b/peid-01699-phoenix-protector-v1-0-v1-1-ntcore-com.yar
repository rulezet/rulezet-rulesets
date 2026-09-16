rule PEiD_01699_Phoenix_Protector_v1_0_v1_1____NTCore_com_ {
  meta:
    description = "[Phoenix Protector v1.0/v1.1 -> NTCore.com]"
    ep_only     = "true"

  strings:
    $a = { 02 6F ?? ?? ?? 0A 0A 06 8D ?? ?? ?? 01 0B 16 0C 38 36 00 00 00 02 08 6F ?? ?? ?? 0A 0D 09 06 08 59 61 D2 13 04 09 1E 63 08 61 D2 13 05 07 08 11 05 1E 62 11 04 60 D1 9D 08 17 58 0C 08 07 8E 69 38 0B 00 00 00 28 ?? ?? ?? 0A 2A 38 EC FF FF FF 3F C0 FF FF FF }

  condition:
    $a
}