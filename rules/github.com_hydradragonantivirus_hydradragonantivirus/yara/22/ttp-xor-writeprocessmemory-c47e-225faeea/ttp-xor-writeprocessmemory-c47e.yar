rule TTP_XOR_WriteProcessMemory_c47e {
  strings:
    $key_c47e = { 93 0c [2] a1 2e [2] a7 1b [2] 89 1b [2] b6 07 }

  condition:
    any of them
}