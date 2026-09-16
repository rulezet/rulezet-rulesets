rule TTP_XOR_WriteProcessMemory_31a2 {
  strings:
    $key_31a2 = { 66 d0 [2] 54 f2 [2] 52 c7 [2] 7c c7 [2] 43 db }

  condition:
    any of them
}