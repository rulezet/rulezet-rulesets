rule TTP_XOR_WriteProcessMemory_68e0 {
  strings:
    $key_68e0 = { 3f 92 [2] 0d b0 [2] 0b 85 [2] 25 85 [2] 1a 99 }

  condition:
    any of them
}