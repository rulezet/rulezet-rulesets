rule TTP_XOR_WriteProcessMemory_e60b {
  strings:
    $key_e60b = { b1 79 [2] 83 5b [2] 85 6e [2] ab 6e [2] 94 72 }

  condition:
    any of them
}