rule PEiD_00324_Borland_C___1992__1994_ {
  meta:
    description = "[Borland C++ 1992, 1994]"
    ep_only     = "true"

  strings:
    $a = { 8C C8 8E D8 8C 1E ?? ?? 8C 06 ?? ?? 8C 06 ?? ?? 8C 06 }

  condition:
    $a
}