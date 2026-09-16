rule TTP_XOR_WriteProcessMemory_32a0 {
  strings:
    $key_32a0 = { 65 d2 [2] 57 f0 [2] 51 c5 [2] 7f c5 [2] 40 d9 }

  condition:
    any of them
}