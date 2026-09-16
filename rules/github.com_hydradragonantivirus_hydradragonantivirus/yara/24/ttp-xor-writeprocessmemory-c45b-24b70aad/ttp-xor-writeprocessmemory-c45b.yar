rule TTP_XOR_WriteProcessMemory_c45b {
  strings:
    $key_c45b = { 93 29 [2] a1 0b [2] a7 3e [2] 89 3e [2] b6 22 }

  condition:
    any of them
}