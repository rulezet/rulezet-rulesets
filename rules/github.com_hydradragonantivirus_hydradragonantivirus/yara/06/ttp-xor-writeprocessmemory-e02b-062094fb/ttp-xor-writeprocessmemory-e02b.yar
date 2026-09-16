rule TTP_XOR_WriteProcessMemory_e02b {
  strings:
    $key_e02b = { b7 59 [2] 85 7b [2] 83 4e [2] ad 4e [2] 92 52 }

  condition:
    any of them
}