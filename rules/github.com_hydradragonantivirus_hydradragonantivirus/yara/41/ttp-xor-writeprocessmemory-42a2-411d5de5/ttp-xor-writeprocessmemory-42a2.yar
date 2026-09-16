rule TTP_XOR_WriteProcessMemory_42a2 {
  strings:
    $key_42a2 = { 15 d0 [2] 27 f2 [2] 21 c7 [2] 0f c7 [2] 30 db }

  condition:
    any of them
}