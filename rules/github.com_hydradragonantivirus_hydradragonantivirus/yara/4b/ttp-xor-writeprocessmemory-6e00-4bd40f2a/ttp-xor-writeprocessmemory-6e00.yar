rule TTP_XOR_WriteProcessMemory_6e00 {
  strings:
    $key_6e00 = { 39 72 [2] 0b 50 [2] 0d 65 [2] 23 65 [2] 1c 79 }

  condition:
    any of them
}