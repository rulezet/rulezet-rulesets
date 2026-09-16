rule PEiD_00906_ILUCRYPT_v4_015__exe_ {
  meta:
    description = "[ILUCRYPT v4.015 [exe]"
    ep_only     = "true"

  strings:
    $a = { 8B EC FA C7 46 F7 ?? ?? 42 81 FA ?? ?? 75 F9 FF 66 F7 }

  condition:
    $a
}