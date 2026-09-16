rule TTP_XOR_WriteProcessMemory_7fd1 {
  strings:
    $key_7fd1 = { 28 a3 [2] 1a 81 [2] 1c b4 [2] 32 b4 [2] 0d a8 }

  condition:
    any of them
}