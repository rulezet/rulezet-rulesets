rule SUSP_PList_Param_Umask_base64 {
  strings:
    $ = "<key>Umask</key>" base64 base64wide

  condition:
    all of them
}