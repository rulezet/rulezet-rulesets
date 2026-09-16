rule TTP_XOR_WriteProcessMemory_41d5 {
  strings:
    $key_41d5 = { 16 a7 [2] 24 85 [2] 22 b0 [2] 0c b0 [2] 33 ac }

  condition:
    any of them
}