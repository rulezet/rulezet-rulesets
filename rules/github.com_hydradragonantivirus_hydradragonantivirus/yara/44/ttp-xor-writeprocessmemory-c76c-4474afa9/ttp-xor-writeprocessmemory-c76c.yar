rule TTP_XOR_WriteProcessMemory_c76c {
  strings:
    $key_c76c = { 90 1e [2] a2 3c [2] a4 09 [2] 8a 09 [2] b5 15 }

  condition:
    any of them
}