rule TTP_XOR_WriteProcessMemory_6fd1 {
  strings:
    $key_6fd1 = { 38 a3 [2] 0a 81 [2] 0c b4 [2] 22 b4 [2] 1d a8 }

  condition:
    any of them
}