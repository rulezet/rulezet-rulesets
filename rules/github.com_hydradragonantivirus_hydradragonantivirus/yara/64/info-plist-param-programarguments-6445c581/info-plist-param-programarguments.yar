rule INFO_PList_Param_ProgramArguments {
  strings:
    $ = "<key>ProgramArguments</key>" ascii wide

  condition:
    all of them
}