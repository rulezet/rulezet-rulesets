rule INFO_PList_Param_ThrottleInterval {
  strings:
    $ = "<key>ThrottleInterval</key>" ascii wide

  condition:
    all of them
}