rule TTP_XOR_WriteProcessMemory_6216 {
  strings:
    $key_6216 = { 35 64 [2] 07 46 [2] 01 73 [2] 2f 73 [2] 10 6f }

  condition:
    any of them
}