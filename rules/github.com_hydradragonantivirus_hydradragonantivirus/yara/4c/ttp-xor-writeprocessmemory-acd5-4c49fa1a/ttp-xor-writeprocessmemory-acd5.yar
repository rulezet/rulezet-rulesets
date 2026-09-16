rule TTP_XOR_WriteProcessMemory_acd5 {
  strings:
    $key_acd5 = { fb a7 [2] c9 85 [2] cf b0 [2] e1 b0 [2] de ac }

  condition:
    any of them
}