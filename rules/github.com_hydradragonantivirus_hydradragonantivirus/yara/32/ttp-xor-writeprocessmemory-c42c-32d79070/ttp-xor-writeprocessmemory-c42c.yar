rule TTP_XOR_WriteProcessMemory_c42c {
  strings:
    $key_c42c = { 93 5e [2] a1 7c [2] a7 49 [2] 89 49 [2] b6 55 }

  condition:
    any of them
}