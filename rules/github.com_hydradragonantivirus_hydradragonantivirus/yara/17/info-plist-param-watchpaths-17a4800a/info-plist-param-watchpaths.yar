rule INFO_PList_Param_WatchPaths {
  strings:
    $ = "<key>WatchPaths</key>" ascii wide

  condition:
    all of them
}