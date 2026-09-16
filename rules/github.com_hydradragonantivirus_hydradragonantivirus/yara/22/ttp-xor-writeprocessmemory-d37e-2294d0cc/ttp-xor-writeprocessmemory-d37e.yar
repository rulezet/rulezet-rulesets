rule TTP_XOR_WriteProcessMemory_d37e {
  strings:
    $key_d37e = { 84 0c [2] b6 2e [2] b0 1b [2] 9e 1b [2] a1 07 }

  condition:
    any of them
}