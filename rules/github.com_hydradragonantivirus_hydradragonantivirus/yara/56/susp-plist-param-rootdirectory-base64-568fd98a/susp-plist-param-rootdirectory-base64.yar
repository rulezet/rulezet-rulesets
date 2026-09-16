rule SUSP_PList_Param_RootDirectory_base64 {
  strings:
    $ = "<key>RootDirectory</key>" base64 base64wide

  condition:
    all of them
}