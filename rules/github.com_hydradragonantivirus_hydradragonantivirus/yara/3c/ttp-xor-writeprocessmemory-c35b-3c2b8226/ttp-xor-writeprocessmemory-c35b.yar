rule TTP_XOR_WriteProcessMemory_c35b {
  strings:
    $key_c35b = { 94 29 [2] a6 0b [2] a0 3e [2] 8e 3e [2] b1 22 }

  condition:
    any of them
}