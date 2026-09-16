rule TTP_XOR_WriteProcessMemory_38a2 {
  strings:
    $key_38a2 = { 6f d0 [2] 5d f2 [2] 5b c7 [2] 75 c7 [2] 4a db }

  condition:
    any of them
}