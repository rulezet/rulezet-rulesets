rule TTP_XOR_WriteProcessMemory_15a2 {
  strings:
    $key_15a2 = { 42 d0 [2] 70 f2 [2] 76 c7 [2] 58 c7 [2] 67 db }

  condition:
    any of them
}