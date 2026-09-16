rule TTP_XOR_WriteProcessMemory_18f2 {
  strings:
    $key_18f2 = { 4f 80 [2] 7d a2 [2] 7b 97 [2] 55 97 [2] 6a 8b }

  condition:
    any of them
}