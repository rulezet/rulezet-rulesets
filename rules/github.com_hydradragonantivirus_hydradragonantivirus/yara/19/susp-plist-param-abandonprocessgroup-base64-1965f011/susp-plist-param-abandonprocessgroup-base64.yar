rule SUSP_PList_Param_AbandonProcessGroup_base64 {
  strings:
    $ = "<key>AbandonProcessGroup</key>" base64 base64wide

  condition:
    all of them
}