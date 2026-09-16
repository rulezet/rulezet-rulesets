rule TTP_XOR_WriteProcessMemory_0ec0 {
  strings:
    $key_0ec0 = { 59 b2 [2] 6b 90 [2] 6d a5 [2] 43 a5 [2] 7c b9 }

  condition:
    any of them
}