rule TTP_XOR_WriteProcessMemory_e8d0 {
  strings:
    $key_e8d0 = { bf a2 [2] 8d 80 [2] 8b b5 [2] a5 b5 [2] 9a a9 }

  condition:
    any of them
}