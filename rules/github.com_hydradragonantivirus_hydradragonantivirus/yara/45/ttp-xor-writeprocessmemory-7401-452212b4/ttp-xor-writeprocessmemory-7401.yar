rule TTP_XOR_WriteProcessMemory_7401 {
  strings:
    $key_7401 = { 23 73 [2] 11 51 [2] 17 64 [2] 39 64 [2] 06 78 }

  condition:
    any of them
}