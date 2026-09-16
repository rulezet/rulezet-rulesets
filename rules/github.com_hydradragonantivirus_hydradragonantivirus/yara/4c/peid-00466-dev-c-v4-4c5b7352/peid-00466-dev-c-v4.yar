rule PEiD_00466_Dev_C___v4_ {
  meta:
    description = "[Dev-C++ v4]"
    ep_only     = "false"

  strings:
    $a = { 55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 ?? ?? ?? 00 FF D0 E8 ?? FF FF FF }

  condition:
    $a
}