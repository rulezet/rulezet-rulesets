rule TTP_XOR_WriteProcessMemory_0d16 {
  strings:
    $key_0d16 = { 5a 64 [2] 68 46 [2] 6e 73 [2] 40 73 [2] 7f 6f }

  condition:
    any of them
}