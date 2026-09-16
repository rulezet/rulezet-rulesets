rule TTP_XOR_WriteProcessMemory_e443 {
  strings:
    $key_e443 = { b3 31 [2] 81 13 [2] 87 26 [2] a9 26 [2] 96 3a }

  condition:
    any of them
}