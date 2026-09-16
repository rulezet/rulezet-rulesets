rule TTP_XOR_WriteProcessMemory_01e0 {
  strings:
    $key_01e0 = { 56 92 [2] 64 b0 [2] 62 85 [2] 4c 85 [2] 73 99 }

  condition:
    any of them
}