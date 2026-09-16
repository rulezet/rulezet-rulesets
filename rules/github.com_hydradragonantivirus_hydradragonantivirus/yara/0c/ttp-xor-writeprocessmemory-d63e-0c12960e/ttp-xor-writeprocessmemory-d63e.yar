rule TTP_XOR_WriteProcessMemory_d63e {
  strings:
    $key_d63e = { 81 4c [2] b3 6e [2] b5 5b [2] 9b 5b [2] a4 47 }

  condition:
    any of them
}