rule TTP_XOR_WriteProcessMemory_c02e {
  strings:
    $key_c02e = { 97 5c [2] a5 7e [2] a3 4b [2] 8d 4b [2] b2 57 }

  condition:
    any of them
}