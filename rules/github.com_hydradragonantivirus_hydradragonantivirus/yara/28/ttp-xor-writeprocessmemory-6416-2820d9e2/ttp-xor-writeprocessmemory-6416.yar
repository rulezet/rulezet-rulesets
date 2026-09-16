rule TTP_XOR_WriteProcessMemory_6416 {
  strings:
    $key_6416 = { 33 64 [2] 01 46 [2] 07 73 [2] 29 73 [2] 16 6f }

  condition:
    any of them
}