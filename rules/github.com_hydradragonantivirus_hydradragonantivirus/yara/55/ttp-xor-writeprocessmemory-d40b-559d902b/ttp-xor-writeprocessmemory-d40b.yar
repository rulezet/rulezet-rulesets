rule TTP_XOR_WriteProcessMemory_d40b {
  strings:
    $key_d40b = { 83 79 [2] b1 5b [2] b7 6e [2] 99 6e [2] a6 72 }

  condition:
    any of them
}