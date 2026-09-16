rule TTP_XOR_WriteProcessMemory_ec00 {
  strings:
    $key_ec00 = { bb 72 [2] 89 50 [2] 8f 65 [2] a1 65 [2] 9e 79 }

  condition:
    any of them
}