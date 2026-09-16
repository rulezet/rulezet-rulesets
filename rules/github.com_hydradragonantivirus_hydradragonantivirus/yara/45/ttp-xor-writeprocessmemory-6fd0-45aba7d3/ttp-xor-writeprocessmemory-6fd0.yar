rule TTP_XOR_WriteProcessMemory_6fd0 {
  strings:
    $key_6fd0 = { 38 a2 [2] 0a 80 [2] 0c b5 [2] 22 b5 [2] 1d a9 }

  condition:
    any of them
}