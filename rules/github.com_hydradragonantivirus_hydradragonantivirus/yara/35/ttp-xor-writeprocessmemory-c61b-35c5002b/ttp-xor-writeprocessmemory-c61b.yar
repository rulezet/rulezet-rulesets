rule TTP_XOR_WriteProcessMemory_c61b {
  strings:
    $key_c61b = { 91 69 [2] a3 4b [2] a5 7e [2] 8b 7e [2] b4 62 }

  condition:
    any of them
}