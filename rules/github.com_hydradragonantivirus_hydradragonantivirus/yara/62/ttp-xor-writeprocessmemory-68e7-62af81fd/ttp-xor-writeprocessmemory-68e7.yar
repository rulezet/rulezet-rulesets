rule TTP_XOR_WriteProcessMemory_68e7 {
  strings:
    $key_68e7 = { 3f 95 [2] 0d b7 [2] 0b 82 [2] 25 82 [2] 1a 9e }

  condition:
    any of them
}