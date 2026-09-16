rule TTP_XOR_WriteProcessMemory_41a2 {
  strings:
    $key_41a2 = { 16 d0 [2] 24 f2 [2] 22 c7 [2] 0c c7 [2] 33 db }

  condition:
    any of them
}