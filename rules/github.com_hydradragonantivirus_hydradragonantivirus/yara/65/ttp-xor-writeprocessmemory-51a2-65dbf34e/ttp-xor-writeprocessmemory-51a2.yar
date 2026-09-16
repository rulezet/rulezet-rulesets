rule TTP_XOR_WriteProcessMemory_51a2 {
  strings:
    $key_51a2 = { 06 d0 [2] 34 f2 [2] 32 c7 [2] 1c c7 [2] 23 db }

  condition:
    any of them
}