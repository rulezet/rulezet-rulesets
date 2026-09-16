rule TTP_XOR_WriteProcessMemory_51f4 {
  strings:
    $key_51f4 = { 06 86 [2] 34 a4 [2] 32 91 [2] 1c 91 [2] 23 8d }

  condition:
    any of them
}