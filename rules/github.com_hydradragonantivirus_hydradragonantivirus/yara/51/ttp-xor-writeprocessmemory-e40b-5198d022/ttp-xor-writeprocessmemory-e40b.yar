rule TTP_XOR_WriteProcessMemory_e40b {
  strings:
    $key_e40b = { b3 79 [2] 81 5b [2] 87 6e [2] a9 6e [2] 96 72 }

  condition:
    any of them
}