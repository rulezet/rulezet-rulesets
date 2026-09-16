rule TTP_XOR_WriteProcessMemory_67f2 {
  strings:
    $key_67f2 = { 30 80 [2] 02 a2 [2] 04 97 [2] 2a 97 [2] 15 8b }

  condition:
    any of them
}