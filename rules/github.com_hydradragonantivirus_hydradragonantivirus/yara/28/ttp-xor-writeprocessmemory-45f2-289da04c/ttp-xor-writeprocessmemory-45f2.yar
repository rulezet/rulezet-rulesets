rule TTP_XOR_WriteProcessMemory_45f2 {
  strings:
    $key_45f2 = { 12 80 [2] 20 a2 [2] 26 97 [2] 08 97 [2] 37 8b }

  condition:
    any of them
}