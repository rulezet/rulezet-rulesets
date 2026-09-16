rule SUSP_PList_Param_ThrottleInterval_xor {
  strings:
    $ = "<key>ThrottleInterval</key>" xor(0x01-0xff)

  condition:
    all of them
}