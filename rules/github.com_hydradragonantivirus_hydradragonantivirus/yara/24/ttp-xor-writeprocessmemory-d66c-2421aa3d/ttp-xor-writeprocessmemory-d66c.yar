rule TTP_XOR_WriteProcessMemory_d66c {
  strings:
    $key_d66c = { 81 1e [2] b3 3c [2] b5 09 [2] 9b 09 [2] a4 15 }

  condition:
    any of them
}