rule TTP_XOR_WriteProcessMemory_0102 {
  strings:
    $key_0102 = { 56 70 [2] 64 52 [2] 62 67 [2] 4c 67 [2] 73 7b }

  condition:
    any of them
}