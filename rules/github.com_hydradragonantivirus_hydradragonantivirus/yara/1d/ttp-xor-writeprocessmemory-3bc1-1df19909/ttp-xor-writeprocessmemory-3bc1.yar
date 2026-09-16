rule TTP_XOR_WriteProcessMemory_3bc1 {
  strings:
    $key_3bc1 = { 6c b3 [2] 5e 91 [2] 58 a4 [2] 76 a4 [2] 49 b8 }

  condition:
    any of them
}