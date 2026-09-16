rule TTP_XOR_WriteProcessMemory_c63b {
  strings:
    $key_c63b = { 91 49 [2] a3 6b [2] a5 5e [2] 8b 5e [2] b4 42 }

  condition:
    any of them
}