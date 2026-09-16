rule TTP_XOR_WriteProcessMemory_c52b {
  strings:
    $key_c52b = { 92 59 [2] a0 7b [2] a6 4e [2] 88 4e [2] b7 52 }

  condition:
    any of them
}