rule TTP_XOR_WriteProcessMemory_3bb0 {
  strings:
    $key_3bb0 = { 6c c2 [2] 5e e0 [2] 58 d5 [2] 76 d5 [2] 49 c9 }

  condition:
    any of them
}