rule TTP_XOR_WriteProcessMemory_d30e {
  strings:
    $key_d30e = { 84 7c [2] b6 5e [2] b0 6b [2] 9e 6b [2] a1 77 }

  condition:
    any of them
}