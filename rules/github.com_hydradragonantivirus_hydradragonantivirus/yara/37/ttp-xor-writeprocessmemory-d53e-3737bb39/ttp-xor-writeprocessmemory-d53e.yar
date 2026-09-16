rule TTP_XOR_WriteProcessMemory_d53e {
  strings:
    $key_d53e = { 82 4c [2] b0 6e [2] b6 5b [2] 98 5b [2] a7 47 }

  condition:
    any of them
}