rule TTP_XOR_WriteProcessMemory_d06b {
  strings:
    $key_d06b = { 87 19 [2] b5 3b [2] b3 0e [2] 9d 0e [2] a2 12 }

  condition:
    any of them
}