rule TTP_XOR_WriteProcessMemory_d60e {
  strings:
    $key_d60e = { 81 7c [2] b3 5e [2] b5 6b [2] 9b 6b [2] a4 77 }

  condition:
    any of them
}