rule TTP_XOR_WriteProcessMemory_1f00 {
  strings:
    $key_1f00 = { 48 72 [2] 7a 50 [2] 7c 65 [2] 52 65 [2] 6d 79 }

  condition:
    any of them
}