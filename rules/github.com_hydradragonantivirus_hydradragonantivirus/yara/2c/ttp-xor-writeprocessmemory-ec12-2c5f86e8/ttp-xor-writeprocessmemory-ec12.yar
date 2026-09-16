rule TTP_XOR_WriteProcessMemory_ec12 {
  strings:
    $key_ec12 = { bb 60 [2] 89 42 [2] 8f 77 [2] a1 77 [2] 9e 6b }

  condition:
    any of them
}