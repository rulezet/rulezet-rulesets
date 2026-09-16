rule TTP_XOR_WriteProcessMemory_72a2 {
  strings:
    $key_72a2 = { 25 d0 [2] 17 f2 [2] 11 c7 [2] 3f c7 [2] 00 db }

  condition:
    any of them
}