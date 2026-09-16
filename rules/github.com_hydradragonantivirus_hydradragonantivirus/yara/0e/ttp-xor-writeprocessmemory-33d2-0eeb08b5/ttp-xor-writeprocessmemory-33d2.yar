rule TTP_XOR_WriteProcessMemory_33d2 {
  strings:
    $key_33d2 = { 64 a0 [2] 56 82 [2] 50 b7 [2] 7e b7 [2] 41 ab }

  condition:
    any of them
}