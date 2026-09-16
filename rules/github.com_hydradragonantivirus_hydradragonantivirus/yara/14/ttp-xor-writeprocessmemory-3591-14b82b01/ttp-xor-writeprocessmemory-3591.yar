rule TTP_XOR_WriteProcessMemory_3591 {
  strings:
    $key_3591 = { 62 e3 [2] 50 c1 [2] 56 f4 [2] 78 f4 [2] 47 e8 }

  condition:
    any of them
}