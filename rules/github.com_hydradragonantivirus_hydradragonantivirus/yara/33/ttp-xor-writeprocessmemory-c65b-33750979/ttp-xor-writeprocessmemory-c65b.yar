rule TTP_XOR_WriteProcessMemory_c65b {
  strings:
    $key_c65b = { 91 29 [2] a3 0b [2] a5 3e [2] 8b 3e [2] b4 22 }

  condition:
    any of them
}