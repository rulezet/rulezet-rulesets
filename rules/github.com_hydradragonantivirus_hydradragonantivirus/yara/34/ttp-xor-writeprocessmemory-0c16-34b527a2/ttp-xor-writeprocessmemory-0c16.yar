rule TTP_XOR_WriteProcessMemory_0c16 {
  strings:
    $key_0c16 = { 5b 64 [2] 69 46 [2] 6f 73 [2] 41 73 [2] 7e 6f }

  condition:
    any of them
}