rule TTP_XOR_WriteProcessMemory_51f1 {
  strings:
    $key_51f1 = { 06 83 [2] 34 a1 [2] 32 94 [2] 1c 94 [2] 23 88 }

  condition:
    any of them
}