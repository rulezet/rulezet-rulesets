rule SUSP_PList_Param_QueueDirectories_base64 {
  strings:
    $ = "<key>QueueDirectories</key>" base64 base64wide

  condition:
    all of them
}