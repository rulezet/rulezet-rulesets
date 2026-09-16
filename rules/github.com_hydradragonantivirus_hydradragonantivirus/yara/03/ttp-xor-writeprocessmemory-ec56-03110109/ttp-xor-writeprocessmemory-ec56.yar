rule TTP_XOR_WriteProcessMemory_ec56 {
  strings:
    $key_ec56 = { bb 24 [2] 89 06 [2] 8f 33 [2] a1 33 [2] 9e 2f }

  condition:
    any of them
}