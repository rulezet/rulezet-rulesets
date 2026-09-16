rule PEiD_02285_Trilobyte_s_JPEG_graphics_Library_ {
  meta:
    description = "[Trilobyte's JPEG graphics Library]"
    ep_only     = "false"

  strings:
    $a = { 84 10 FF FF FF FF 1E 00 01 10 08 00 00 00 00 00 }

  condition:
    $a
}