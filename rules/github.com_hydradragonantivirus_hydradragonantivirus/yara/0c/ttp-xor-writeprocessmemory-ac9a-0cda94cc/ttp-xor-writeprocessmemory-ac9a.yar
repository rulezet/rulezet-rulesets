rule TTP_XOR_WriteProcessMemory_ac9a {
  strings:
    $key_ac9a = { fb e8 [2] c9 ca [2] cf ff [2] e1 ff [2] de e3 }

  condition:
    any of them
}