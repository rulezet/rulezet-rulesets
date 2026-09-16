rule PEiD_00402_CorelDraw_CMX_Graphics_format_ {
  meta:
    description = "[CorelDraw CMX Graphics format]"
    ep_only     = "false"

  strings:
    $a = { 52 49 46 46 ?? ?? ?? ?? 43 4D 58 31 }

  condition:
    $a
}