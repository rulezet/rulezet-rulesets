rule TTP_XOR_WriteProcessMemory_23c0 {
  strings:
    $key_23c0 = { 74 b2 [2] 46 90 [2] 40 a5 [2] 6e a5 [2] 51 b9 }

  condition:
    any of them
}