rule TTP_XOR_WriteProcessMemory_c61e {
  strings:
    $key_c61e = { 91 6c [2] a3 4e [2] a5 7b [2] 8b 7b [2] b4 67 }

  condition:
    any of them
}