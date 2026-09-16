rule TTP_XOR_WriteProcessMemory_c55b {
  strings:
    $key_c55b = { 92 29 [2] a0 0b [2] a6 3e [2] 88 3e [2] b7 22 }

  condition:
    any of them
}