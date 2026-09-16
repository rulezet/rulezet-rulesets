rule TTP_XOR_WriteProcessMemory_6f00 {
  strings:
    $key_6f00 = { 38 72 [2] 0a 50 [2] 0c 65 [2] 22 65 [2] 1d 79 }

  condition:
    any of them
}