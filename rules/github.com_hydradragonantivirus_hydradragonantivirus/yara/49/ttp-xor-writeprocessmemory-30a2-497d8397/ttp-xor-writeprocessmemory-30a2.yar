rule TTP_XOR_WriteProcessMemory_30a2 {
  strings:
    $key_30a2 = { 67 d0 [2] 55 f2 [2] 53 c7 [2] 7d c7 [2] 42 db }

  condition:
    any of them
}