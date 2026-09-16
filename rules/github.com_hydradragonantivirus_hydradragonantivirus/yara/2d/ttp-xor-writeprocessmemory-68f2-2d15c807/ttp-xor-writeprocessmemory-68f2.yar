rule TTP_XOR_WriteProcessMemory_68f2 {
  strings:
    $key_68f2 = { 3f 80 [2] 0d a2 [2] 0b 97 [2] 25 97 [2] 1a 8b }

  condition:
    any of them
}