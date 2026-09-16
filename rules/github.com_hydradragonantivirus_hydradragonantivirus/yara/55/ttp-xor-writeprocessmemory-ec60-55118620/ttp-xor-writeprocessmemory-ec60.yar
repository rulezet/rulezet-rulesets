rule TTP_XOR_WriteProcessMemory_ec60 {
  strings:
    $key_ec60 = { bb 12 [2] 89 30 [2] 8f 05 [2] a1 05 [2] 9e 19 }

  condition:
    any of them
}