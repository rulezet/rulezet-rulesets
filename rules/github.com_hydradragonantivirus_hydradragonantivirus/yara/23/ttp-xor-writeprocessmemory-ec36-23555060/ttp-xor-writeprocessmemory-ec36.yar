rule TTP_XOR_WriteProcessMemory_ec36 {
  strings:
    $key_ec36 = { bb 44 [2] 89 66 [2] 8f 53 [2] a1 53 [2] 9e 4f }

  condition:
    any of them
}