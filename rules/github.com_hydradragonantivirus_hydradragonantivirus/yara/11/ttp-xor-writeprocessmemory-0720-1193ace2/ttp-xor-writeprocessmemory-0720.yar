rule TTP_XOR_WriteProcessMemory_0720 {
  strings:
    $key_0720 = { 50 52 [2] 62 70 [2] 64 45 [2] 4a 45 [2] 75 59 }

  condition:
    any of them
}