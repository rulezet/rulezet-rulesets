rule TTP_XOR_WriteProcessMemory_4791 {
  strings:
    $key_4791 = { 10 e3 [2] 22 c1 [2] 24 f4 [2] 0a f4 [2] 35 e8 }

  condition:
    any of them
}