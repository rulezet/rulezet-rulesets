rule TTP_XOR_WriteProcessMemory_03a2 {
  strings:
    $key_03a2 = { 54 d0 [2] 66 f2 [2] 60 c7 [2] 4e c7 [2] 71 db }

  condition:
    any of them
}