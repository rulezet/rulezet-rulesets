rule TTP_XOR_WriteProcessMemory_33d1 {
  strings:
    $key_33d1 = { 64 a3 [2] 56 81 [2] 50 b4 [2] 7e b4 [2] 41 a8 }

  condition:
    any of them
}