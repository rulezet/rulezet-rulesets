rule TTP_XOR_WriteProcessMemory_d45b {
  strings:
    $key_d45b = { 83 29 [2] b1 0b [2] b7 3e [2] 99 3e [2] a6 22 }

  condition:
    any of them
}