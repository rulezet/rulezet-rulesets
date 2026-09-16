rule TTP_XOR_WriteProcessMemory_46a2 {
  strings:
    $key_46a2 = { 11 d0 [2] 23 f2 [2] 25 c7 [2] 0b c7 [2] 34 db }

  condition:
    any of them
}