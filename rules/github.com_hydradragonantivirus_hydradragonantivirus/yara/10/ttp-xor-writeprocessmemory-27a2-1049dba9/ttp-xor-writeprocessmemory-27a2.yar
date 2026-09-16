rule TTP_XOR_WriteProcessMemory_27a2 {
  strings:
    $key_27a2 = { 70 d0 [2] 42 f2 [2] 44 c7 [2] 6a c7 [2] 55 db }

  condition:
    any of them
}