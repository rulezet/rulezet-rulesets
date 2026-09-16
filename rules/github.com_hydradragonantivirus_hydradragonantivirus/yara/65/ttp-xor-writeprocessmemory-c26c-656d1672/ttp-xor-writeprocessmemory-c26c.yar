rule TTP_XOR_WriteProcessMemory_c26c {
  strings:
    $key_c26c = { 95 1e [2] a7 3c [2] a1 09 [2] 8f 09 [2] b0 15 }

  condition:
    any of them
}