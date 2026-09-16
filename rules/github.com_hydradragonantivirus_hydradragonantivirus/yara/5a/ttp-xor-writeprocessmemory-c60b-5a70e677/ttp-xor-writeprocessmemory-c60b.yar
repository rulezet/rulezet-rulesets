rule TTP_XOR_WriteProcessMemory_c60b {
  strings:
    $key_c60b = { 91 79 [2] a3 5b [2] a5 6e [2] 8b 6e [2] b4 72 }

  condition:
    any of them
}