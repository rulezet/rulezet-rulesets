rule SUSP_PList_Param_QueueDirectories_xor {
  strings:
    $ = "<key>QueueDirectories</key>" xor(0x01-0xff)

  condition:
    all of them
}