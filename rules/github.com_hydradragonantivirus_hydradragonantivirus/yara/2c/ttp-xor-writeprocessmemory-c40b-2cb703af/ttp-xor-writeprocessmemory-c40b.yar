rule TTP_XOR_WriteProcessMemory_c40b {
  strings:
    $key_c40b = { 93 79 [2] a1 5b [2] a7 6e [2] 89 6e [2] b6 72 }

  condition:
    any of them
}