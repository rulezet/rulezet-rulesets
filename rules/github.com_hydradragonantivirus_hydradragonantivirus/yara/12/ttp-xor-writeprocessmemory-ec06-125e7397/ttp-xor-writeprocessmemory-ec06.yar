rule TTP_XOR_WriteProcessMemory_ec06 {
  strings:
    $key_ec06 = { bb 74 [2] 89 56 [2] 8f 63 [2] a1 63 [2] 9e 7f }

  condition:
    any of them
}