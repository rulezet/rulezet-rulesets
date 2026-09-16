rule TTP_XOR_WriteProcessMemory_28a2 {
  strings:
    $key_28a2 = { 7f d0 [2] 4d f2 [2] 4b c7 [2] 65 c7 [2] 5a db }

  condition:
    any of them
}