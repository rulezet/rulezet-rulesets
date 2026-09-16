rule TTP_XOR_WriteProcessMemory_0140 {
  strings:
    $key_0140 = { 56 32 [2] 64 10 [2] 62 25 [2] 4c 25 [2] 73 39 }

  condition:
    any of them
}