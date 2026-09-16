rule TTP_XOR_WriteProcessMemory_68f9 {
  strings:
    $key_68f9 = { 3f 8b [2] 0d a9 [2] 0b 9c [2] 25 9c [2] 1a 80 }

  condition:
    any of them
}