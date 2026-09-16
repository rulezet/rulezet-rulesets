rule TTP_XOR_WriteProcessMemory_51f2 {
  strings:
    $key_51f2 = { 06 80 [2] 34 a2 [2] 32 97 [2] 1c 97 [2] 23 8b }

  condition:
    any of them
}