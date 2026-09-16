rule TTP_XOR_WriteProcessMemory_c75c {
  strings:
    $key_c75c = { 90 2e [2] a2 0c [2] a4 39 [2] 8a 39 [2] b5 25 }

  condition:
    any of them
}