rule TTP_XOR_WriteProcessMemory_aae6 {
  strings:
    $key_aae6 = { fd 94 [2] cf b6 [2] c9 83 [2] e7 83 [2] d8 9f }

  condition:
    any of them
}