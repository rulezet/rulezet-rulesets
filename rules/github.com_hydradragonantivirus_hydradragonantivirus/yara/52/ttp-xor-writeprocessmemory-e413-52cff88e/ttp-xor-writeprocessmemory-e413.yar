rule TTP_XOR_WriteProcessMemory_e413 {
  strings:
    $key_e413 = { b3 61 [2] 81 43 [2] 87 76 [2] a9 76 [2] 96 6a }

  condition:
    any of them
}