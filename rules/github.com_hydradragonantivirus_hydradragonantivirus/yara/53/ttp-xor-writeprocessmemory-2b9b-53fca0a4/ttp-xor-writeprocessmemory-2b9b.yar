rule TTP_XOR_WriteProcessMemory_2b9b {
  strings:
    $key_2b9b = { 7c e9 [2] 4e cb [2] 48 fe [2] 66 fe [2] 59 e2 }

  condition:
    any of them
}