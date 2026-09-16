rule TTP_XOR_WriteProcessMemory_c22b {
  strings:
    $key_c22b = { 95 59 [2] a7 7b [2] a1 4e [2] 8f 4e [2] b0 52 }

  condition:
    any of them
}