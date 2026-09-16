rule TTP_XOR_WriteProcessMemory_3767 {
  strings:
    $key_3767 = { 60 15 [2] 52 37 [2] 54 02 [2] 7a 02 [2] 45 1e }

  condition:
    any of them
}