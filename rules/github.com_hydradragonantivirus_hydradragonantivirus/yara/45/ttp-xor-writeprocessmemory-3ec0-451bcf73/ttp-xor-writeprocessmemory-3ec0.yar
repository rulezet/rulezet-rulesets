rule TTP_XOR_WriteProcessMemory_3ec0 {
  strings:
    $key_3ec0 = { 69 b2 [2] 5b 90 [2] 5d a5 [2] 73 a5 [2] 4c b9 }

  condition:
    any of them
}