rule TTP_XOR_WriteProcessMemory_d64e {
  strings:
    $key_d64e = { 81 3c [2] b3 1e [2] b5 2b [2] 9b 2b [2] a4 37 }

  condition:
    any of them
}