rule TTP_XOR_WriteProcessMemory_ec41 {
  strings:
    $key_ec41 = { bb 33 [2] 89 11 [2] 8f 24 [2] a1 24 [2] 9e 38 }

  condition:
    any of them
}