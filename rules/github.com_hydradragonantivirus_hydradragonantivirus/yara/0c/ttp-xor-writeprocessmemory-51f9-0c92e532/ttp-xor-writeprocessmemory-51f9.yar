rule TTP_XOR_WriteProcessMemory_51f9 {
  strings:
    $key_51f9 = { 06 8b [2] 34 a9 [2] 32 9c [2] 1c 9c [2] 23 80 }

  condition:
    any of them
}