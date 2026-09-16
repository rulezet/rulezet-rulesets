rule PEiD_00920_Inno_Setup_Module_ {
  meta:
    description = "[Inno Setup Module]"
    ep_only     = "true"

  strings:
    $a = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43 }

  condition:
    $a
}