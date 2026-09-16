rule PEiD_00401_CorelDraw_8_CDR_Graphics_format_ {
  meta:
    description = "[CorelDraw 8 CDR Graphics format]"
    ep_only     = "false"

  strings:
    $a = { 52 49 46 46 ?? ?? ?? ?? 43 44 52 38 }

  condition:
    $a
}