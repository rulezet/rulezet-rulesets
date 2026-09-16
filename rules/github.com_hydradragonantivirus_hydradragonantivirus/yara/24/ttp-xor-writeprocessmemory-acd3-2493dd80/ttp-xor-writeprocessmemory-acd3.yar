rule TTP_XOR_WriteProcessMemory_acd3 {
  strings:
    $key_acd3 = { fb a1 [2] c9 83 [2] cf b6 [2] e1 b6 [2] de aa }

  condition:
    any of them
}