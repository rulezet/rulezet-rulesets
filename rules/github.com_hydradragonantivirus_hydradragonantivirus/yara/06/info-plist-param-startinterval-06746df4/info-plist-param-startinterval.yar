rule INFO_PList_Param_StartInterval {
  strings:
    $ = "<key>StartInterval</key>" ascii wide

  condition:
    all of them
}