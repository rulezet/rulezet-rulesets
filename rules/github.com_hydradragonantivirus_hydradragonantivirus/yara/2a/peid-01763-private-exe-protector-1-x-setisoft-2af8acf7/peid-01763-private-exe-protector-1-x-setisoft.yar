rule PEiD_01763_Private_Exe_Protector_1_x____setisoft_ {
  meta:
    description = "[Private Exe Protector 1.x -> setisoft]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? ?? B9 ?? 90 01 ?? BE ?? 10 40 ?? 68 50 91 41 ?? 68 01 ?? ?? ?? C3 }

  condition:
    $a
}