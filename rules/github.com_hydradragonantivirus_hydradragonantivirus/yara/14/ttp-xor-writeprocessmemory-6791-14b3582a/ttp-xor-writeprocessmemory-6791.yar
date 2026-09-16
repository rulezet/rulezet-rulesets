rule TTP_XOR_WriteProcessMemory_6791 {
  strings:
    $key_6791 = { 30 e3 [2] 02 c1 [2] 04 f4 [2] 2a f4 [2] 15 e8 }

  condition:
    any of them
}