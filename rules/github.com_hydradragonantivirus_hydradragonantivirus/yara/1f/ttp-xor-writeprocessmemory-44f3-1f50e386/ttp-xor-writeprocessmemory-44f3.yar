rule TTP_XOR_WriteProcessMemory_44f3 {
  strings:
    $key_44f3 = { 13 81 [2] 21 a3 [2] 27 96 [2] 09 96 [2] 36 8a }

  condition:
    any of them
}