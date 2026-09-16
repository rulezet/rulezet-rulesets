rule TTP_XOR_WriteProcessMemory_2a00 {
  strings:
    $key_2a00 = { 7d 72 [2] 4f 50 [2] 49 65 [2] 67 65 [2] 58 79 }

  condition:
    any of them
}