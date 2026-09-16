rule TTP_XOR_WriteProcessMemory_ec42 {
  strings:
    $key_ec42 = { bb 30 [2] 89 12 [2] 8f 27 [2] a1 27 [2] 9e 3b }

  condition:
    any of them
}