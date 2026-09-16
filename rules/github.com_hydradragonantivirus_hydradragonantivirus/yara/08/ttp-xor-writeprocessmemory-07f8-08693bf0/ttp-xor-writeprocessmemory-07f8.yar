rule TTP_XOR_WriteProcessMemory_07f8 {
  strings:
    $key_07f8 = { 50 8a [2] 62 a8 [2] 64 9d [2] 4a 9d [2] 75 81 }

  condition:
    any of them
}