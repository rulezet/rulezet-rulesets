rule TTP_XOR_WriteProcessMemory_2ec0 {
  strings:
    $key_2ec0 = { 79 b2 [2] 4b 90 [2] 4d a5 [2] 63 a5 [2] 5c b9 }

  condition:
    any of them
}