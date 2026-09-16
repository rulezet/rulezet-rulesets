rule PEiD_01700_Phonebook_configuration_file_Version__v3__v4_ {
  meta:
    description = "[Phonebook configuration file Version %v3.%v4]"
    ep_only     = "false"

  strings:
    $a = { 50 68 6F 6E 65 62 6F 6F 6B ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 63 6F }

  condition:
    $a
}