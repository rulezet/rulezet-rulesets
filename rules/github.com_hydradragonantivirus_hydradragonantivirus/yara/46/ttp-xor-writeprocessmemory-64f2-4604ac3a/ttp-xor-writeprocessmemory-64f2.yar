rule TTP_XOR_WriteProcessMemory_64f2 {
  strings:
    $key_64f2 = { 33 80 [2] 01 a2 [2] 07 97 [2] 29 97 [2] 16 8b }

  condition:
    any of them
}