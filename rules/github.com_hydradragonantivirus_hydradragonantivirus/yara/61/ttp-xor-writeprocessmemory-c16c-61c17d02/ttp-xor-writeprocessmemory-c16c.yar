rule TTP_XOR_WriteProcessMemory_c16c {
  strings:
    $key_c16c = { 96 1e [2] a4 3c [2] a2 09 [2] 8c 09 [2] b3 15 }

  condition:
    any of them
}