rule TTP_XOR_WriteProcessMemory_44a2 {
  strings:
    $key_44a2 = { 13 d0 [2] 21 f2 [2] 27 c7 [2] 09 c7 [2] 36 db }

  condition:
    any of them
}