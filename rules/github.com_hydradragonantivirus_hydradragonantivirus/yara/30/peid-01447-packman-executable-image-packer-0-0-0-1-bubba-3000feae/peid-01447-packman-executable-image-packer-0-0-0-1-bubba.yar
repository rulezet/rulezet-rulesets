rule PEiD_01447_Packman_Executable_Image_Packer_0_0_0_1____bubba_ {
  meta:
    description = "[Packman Executable Image Packer 0.0.0.1 -> bubba]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 58 8D A8 ?? ?? FF FF 8D 98 ?? ?? ?? FF }

  condition:
    $a
}