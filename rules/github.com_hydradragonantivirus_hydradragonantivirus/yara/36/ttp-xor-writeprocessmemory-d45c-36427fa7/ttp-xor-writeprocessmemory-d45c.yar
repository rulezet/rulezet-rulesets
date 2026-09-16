rule TTP_XOR_WriteProcessMemory_d45c {
  strings:
    $key_d45c = { 83 2e [2] b1 0c [2] b7 39 [2] 99 39 [2] a6 25 }

  condition:
    any of them
}