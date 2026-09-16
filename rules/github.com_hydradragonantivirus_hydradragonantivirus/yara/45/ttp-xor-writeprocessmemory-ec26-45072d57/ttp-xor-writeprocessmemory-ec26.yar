rule TTP_XOR_WriteProcessMemory_ec26 {
  strings:
    $key_ec26 = { bb 54 [2] 89 76 [2] 8f 43 [2] a1 43 [2] 9e 5f }

  condition:
    any of them
}