rule TTP_XOR_WriteProcessMemory_17f2 {
  strings:
    $key_17f2 = { 40 80 [2] 72 a2 [2] 74 97 [2] 5a 97 [2] 65 8b }

  condition:
    any of them
}