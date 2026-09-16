rule SUSP_PList_Param_EnvironmentVariables_xor {
  strings:
    $ = "<key>EnvironmentVariables</key>" xor(0x01-0xff)

  condition:
    all of them
}