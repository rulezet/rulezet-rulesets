rule TTP_XOR_WriteProcessMemory_c36c {
  strings:
    $key_c36c = { 94 1e [2] a6 3c [2] a0 09 [2] 8e 09 [2] b1 15 }

  condition:
    any of them
}