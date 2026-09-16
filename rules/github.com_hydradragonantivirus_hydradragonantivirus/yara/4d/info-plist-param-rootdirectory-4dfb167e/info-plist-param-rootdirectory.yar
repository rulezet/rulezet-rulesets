rule INFO_PList_Param_RootDirectory {
  strings:
    $ = "<key>RootDirectory</key>" ascii wide

  condition:
    all of them
}