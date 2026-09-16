rule TTP_XOR_WriteProcessMemory_41d0 {
  strings:
    $key_41d0 = { 16 a2 [2] 24 80 [2] 22 b5 [2] 0c b5 [2] 33 a9 }

  condition:
    any of them
}