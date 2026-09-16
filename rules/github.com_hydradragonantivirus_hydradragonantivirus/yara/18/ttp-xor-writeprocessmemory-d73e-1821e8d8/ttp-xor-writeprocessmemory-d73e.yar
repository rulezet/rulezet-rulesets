rule TTP_XOR_WriteProcessMemory_d73e {
  strings:
    $key_d73e = { 80 4c [2] b2 6e [2] b4 5b [2] 9a 5b [2] a5 47 }

  condition:
    any of them
}