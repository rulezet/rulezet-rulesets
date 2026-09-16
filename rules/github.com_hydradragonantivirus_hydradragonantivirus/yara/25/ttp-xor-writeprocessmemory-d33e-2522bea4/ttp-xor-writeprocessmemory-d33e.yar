rule TTP_XOR_WriteProcessMemory_d33e {
  strings:
    $key_d33e = { 84 4c [2] b6 6e [2] b0 5b [2] 9e 5b [2] a1 47 }

  condition:
    any of them
}