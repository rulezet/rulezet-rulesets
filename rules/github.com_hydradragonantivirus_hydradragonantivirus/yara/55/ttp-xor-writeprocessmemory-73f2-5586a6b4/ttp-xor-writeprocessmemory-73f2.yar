rule TTP_XOR_WriteProcessMemory_73f2 {
  strings:
    $key_73f2 = { 24 80 [2] 16 a2 [2] 10 97 [2] 3e 97 [2] 01 8b }

  condition:
    any of them
}