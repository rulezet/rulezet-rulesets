rule TTP_XOR_WriteProcessMemory_0126 {
  strings:
    $key_0126 = { 56 54 [2] 64 76 [2] 62 43 [2] 4c 43 [2] 73 5f }

  condition:
    any of them
}