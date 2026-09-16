rule PEiD_03410_Vx__Number_One_ {
  meta:
    description = "[Vx: Number One]"
    ep_only     = "true"

  strings:
    $a = { F9 07 3C 53 6D 69 6C 65 3E E8 }

  condition:
    $a
}