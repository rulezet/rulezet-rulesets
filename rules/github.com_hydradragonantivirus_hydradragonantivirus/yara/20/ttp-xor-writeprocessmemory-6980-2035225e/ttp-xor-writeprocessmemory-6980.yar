rule TTP_XOR_WriteProcessMemory_6980 {
  strings:
    $key_6980 = { 3e f2 [2] 0c d0 [2] 0a e5 [2] 24 e5 [2] 1b f9 }

  condition:
    any of them
}