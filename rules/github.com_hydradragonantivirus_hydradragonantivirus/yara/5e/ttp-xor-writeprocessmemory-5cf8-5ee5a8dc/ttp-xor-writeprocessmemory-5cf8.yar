rule TTP_XOR_WriteProcessMemory_5cf8 {
  strings:
    $key_5cf8 = { 0b 8a [2] 39 a8 [2] 3f 9d [2] 11 9d [2] 2e 81 }

  condition:
    any of them
}