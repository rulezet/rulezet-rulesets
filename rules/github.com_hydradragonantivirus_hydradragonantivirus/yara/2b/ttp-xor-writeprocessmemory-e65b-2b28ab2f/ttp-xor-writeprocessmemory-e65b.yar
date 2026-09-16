rule TTP_XOR_WriteProcessMemory_e65b {
  strings:
    $key_e65b = { b1 29 [2] 83 0b [2] 85 3e [2] ab 3e [2] 94 22 }

  condition:
    any of them
}