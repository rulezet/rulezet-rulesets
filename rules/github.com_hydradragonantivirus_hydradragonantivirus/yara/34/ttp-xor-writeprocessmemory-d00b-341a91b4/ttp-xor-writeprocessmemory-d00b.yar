rule TTP_XOR_WriteProcessMemory_d00b {
  strings:
    $key_d00b = { 87 79 [2] b5 5b [2] b3 6e [2] 9d 6e [2] a2 72 }

  condition:
    any of them
}