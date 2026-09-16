rule PEiD_00930_Interchange_Format_File__IFF___type_WVQA_ {
  meta:
    description = "[Interchange Format File (IFF), type WVQA]"
    ep_only     = "false"

  strings:
    $a = { 46 4F 52 4D ?? ?? ?? ?? 57 56 51 41 56 51 48 44 }

  condition:
    $a
}