rule TTP_XOR_WriteProcessMemory_51b5 {
  strings:
    $key_51b5 = { 06 c7 [2] 34 e5 [2] 32 d0 [2] 1c d0 [2] 23 cc }

  condition:
    any of them
}