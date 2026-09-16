rule TTP_XOR_WriteProcessMemory_16e6 {
  strings:
    $key_16e6 = { 41 94 [2] 73 b6 [2] 75 83 [2] 5b 83 [2] 64 9f }

  condition:
    any of them
}