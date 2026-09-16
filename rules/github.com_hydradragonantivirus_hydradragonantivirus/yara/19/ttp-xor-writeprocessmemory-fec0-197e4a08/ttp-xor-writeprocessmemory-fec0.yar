rule TTP_XOR_WriteProcessMemory_fec0 {
  strings:
    $key_fec0 = { a9 b2 [2] 9b 90 [2] 9d a5 [2] b3 a5 [2] 8c b9 }

  condition:
    any of them
}