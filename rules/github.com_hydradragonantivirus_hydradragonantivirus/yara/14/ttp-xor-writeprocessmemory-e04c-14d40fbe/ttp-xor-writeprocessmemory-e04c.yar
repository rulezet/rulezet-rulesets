rule TTP_XOR_WriteProcessMemory_e04c {
  strings:
    $key_e04c = { b7 3e [2] 85 1c [2] 83 29 [2] ad 29 [2] 92 35 }

  condition:
    any of them
}