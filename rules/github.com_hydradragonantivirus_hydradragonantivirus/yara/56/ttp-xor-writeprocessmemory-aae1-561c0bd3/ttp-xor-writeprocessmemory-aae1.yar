rule TTP_XOR_WriteProcessMemory_aae1 {
  strings:
    $key_aae1 = { fd 93 [2] cf b1 [2] c9 84 [2] e7 84 [2] d8 98 }

  condition:
    any of them
}