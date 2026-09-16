rule PEiD_02507_VMProtect_0_x____PolyTech_ {
  meta:
    description = "[VMProtect 0.x -> PolyTech]"
    ep_only     = "true"

  strings:
    $a = "[ VMProtect "

  condition:
    $a
}