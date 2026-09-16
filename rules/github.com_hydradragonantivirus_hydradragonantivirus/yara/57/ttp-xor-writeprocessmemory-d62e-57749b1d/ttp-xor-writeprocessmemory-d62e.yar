rule TTP_XOR_WriteProcessMemory_d62e {
  strings:
    $key_d62e = { 81 5c [2] b3 7e [2] b5 4b [2] 9b 4b [2] a4 57 }

  condition:
    any of them
}