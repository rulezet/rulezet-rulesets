rule TTP_XOR_WriteProcessMemory_d20e {
  strings:
    $key_d20e = { 85 7c [2] b7 5e [2] b1 6b [2] 9f 6b [2] a0 77 }

  condition:
    any of them
}