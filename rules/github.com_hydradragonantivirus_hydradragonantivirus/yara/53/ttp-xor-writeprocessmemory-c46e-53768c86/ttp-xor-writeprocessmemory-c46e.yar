rule TTP_XOR_WriteProcessMemory_c46e {
  strings:
    $key_c46e = { 93 1c [2] a1 3e [2] a7 0b [2] 89 0b [2] b6 17 }

  condition:
    any of them
}