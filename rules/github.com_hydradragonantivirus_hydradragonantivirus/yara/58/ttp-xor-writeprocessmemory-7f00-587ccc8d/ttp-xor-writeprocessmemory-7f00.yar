rule TTP_XOR_WriteProcessMemory_7f00 {
  strings:
    $key_7f00 = { 28 72 [2] 1a 50 [2] 1c 65 [2] 32 65 [2] 0d 79 }

  condition:
    any of them
}