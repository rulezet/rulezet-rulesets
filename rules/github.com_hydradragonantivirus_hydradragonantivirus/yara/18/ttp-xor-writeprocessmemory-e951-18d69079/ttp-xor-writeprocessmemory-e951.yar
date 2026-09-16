rule TTP_XOR_WriteProcessMemory_e951 {
  strings:
    $key_e951 = { be 23 [2] 8c 01 [2] 8a 34 [2] a4 34 [2] 9b 28 }

  condition:
    any of them
}