rule TTP_XOR_WriteProcessMemory_02a0 {
  strings:
    $key_02a0 = { 55 d2 [2] 67 f0 [2] 61 c5 [2] 4f c5 [2] 70 d9 }

  condition:
    any of them
}