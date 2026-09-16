rule TTP_XOR_WriteProcessMemory_c62b {
  strings:
    $key_c62b = { 91 59 [2] a3 7b [2] a5 4e [2] 8b 4e [2] b4 52 }

  condition:
    any of them
}