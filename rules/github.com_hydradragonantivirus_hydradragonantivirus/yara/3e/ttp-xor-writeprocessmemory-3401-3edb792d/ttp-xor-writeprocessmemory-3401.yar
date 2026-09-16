rule TTP_XOR_WriteProcessMemory_3401 {
  strings:
    $key_3401 = { 63 73 [2] 51 51 [2] 57 64 [2] 79 64 [2] 46 78 }

  condition:
    any of them
}