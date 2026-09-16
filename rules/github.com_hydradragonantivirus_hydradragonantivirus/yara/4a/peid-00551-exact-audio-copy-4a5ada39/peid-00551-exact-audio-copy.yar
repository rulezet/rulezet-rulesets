rule PEiD_00551_Exact_Audio_Copy_ {
  meta:
    description = "[Exact Audio Copy]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? ?? 00 31 ED 55 89 E5 81 EC ?? 00 00 00 8D BD ?? FF FF FF B9 ?? 00 00 00 }

  condition:
    $a
}