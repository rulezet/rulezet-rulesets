rule TTP_XOR_WriteProcessMemory_01c0 {
  strings:
    $key_01c0 = { 56 b2 [2] 64 90 [2] 62 a5 [2] 4c a5 [2] 73 b9 }

  condition:
    any of them
}