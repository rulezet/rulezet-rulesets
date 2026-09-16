rule TTP_XOR_WriteProcessMemory_ec21 {
  strings:
    $key_ec21 = { bb 53 [2] 89 71 [2] 8f 44 [2] a1 44 [2] 9e 58 }

  condition:
    any of them
}