rule TTP_XOR_WriteProcessMemory_64a2 {
  strings:
    $key_64a2 = { 33 d0 [2] 01 f2 [2] 07 c7 [2] 29 c7 [2] 16 db }

  condition:
    any of them
}