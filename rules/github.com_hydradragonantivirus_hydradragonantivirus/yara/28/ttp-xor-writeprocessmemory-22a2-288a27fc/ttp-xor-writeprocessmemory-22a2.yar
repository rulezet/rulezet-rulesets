rule TTP_XOR_WriteProcessMemory_22a2 {
  strings:
    $key_22a2 = { 75 d0 [2] 47 f2 [2] 41 c7 [2] 6f c7 [2] 50 db }

  condition:
    any of them
}