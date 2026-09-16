rule PEiD_02479_Utah_RLE_Graphics_format_ {
  meta:
    description = "[Utah RLE Graphics format]"
    ep_only     = "false"

  strings:
    $a = { 52 CC 00 00 00 00 ?? ?? ?? ?? 09 ?? 08 ?? 08 }

  condition:
    $a
}