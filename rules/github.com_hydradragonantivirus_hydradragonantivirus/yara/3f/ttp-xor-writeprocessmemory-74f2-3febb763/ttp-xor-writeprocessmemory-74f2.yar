rule TTP_XOR_WriteProcessMemory_74f2 {
  strings:
    $key_74f2 = { 23 80 [2] 11 a2 [2] 17 97 [2] 39 97 [2] 06 8b }

  condition:
    any of them
}