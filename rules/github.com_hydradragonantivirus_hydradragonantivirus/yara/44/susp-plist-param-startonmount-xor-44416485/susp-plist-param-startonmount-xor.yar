rule SUSP_PList_Param_StartOnMount_xor {
  strings:
    $ = "<key>StartOnMount</key>" xor(0x01-0xff)

  condition:
    all of them
}