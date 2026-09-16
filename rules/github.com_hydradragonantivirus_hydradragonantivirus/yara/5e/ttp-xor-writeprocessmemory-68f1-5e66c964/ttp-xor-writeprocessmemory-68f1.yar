rule TTP_XOR_WriteProcessMemory_68f1 {
  strings:
    $key_68f1 = { 3f 83 [2] 0d a1 [2] 0b 94 [2] 25 94 [2] 1a 88 }

  condition:
    any of them
}