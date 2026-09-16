rule TTP_XOR_WriteProcessMemory_ec03 {
  strings:
    $key_ec03 = { bb 71 [2] 89 53 [2] 8f 66 [2] a1 66 [2] 9e 7a }

  condition:
    any of them
}