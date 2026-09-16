rule TTP_XOR_WriteProcessMemory_44f2 {
  strings:
    $key_44f2 = { 13 80 [2] 21 a2 [2] 27 97 [2] 09 97 [2] 36 8b }

  condition:
    any of them
}