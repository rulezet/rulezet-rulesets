rule TTP_XOR_WriteProcessMemory_ec53 {
  strings:
    $key_ec53 = { bb 21 [2] 89 03 [2] 8f 36 [2] a1 36 [2] 9e 2a }

  condition:
    any of them
}