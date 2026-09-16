rule SUSP_PList_Param_ThrottleInterval_base64 {
  strings:
    $ = "<key>ThrottleInterval</key>" base64 base64wide

  condition:
    all of them
}