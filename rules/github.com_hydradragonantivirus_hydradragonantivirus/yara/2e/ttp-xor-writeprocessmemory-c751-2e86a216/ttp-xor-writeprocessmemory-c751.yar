rule TTP_XOR_WriteProcessMemory_c751 {
  strings:
    $key_c751 = { 90 23 [2] a2 01 [2] a4 34 [2] 8a 34 [2] b5 28 }

  condition:
    any of them
}