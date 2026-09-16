rule TTP_XOR_WriteProcessMemory_d31c {
  strings:
    $key_d31c = { 84 6e [2] b6 4c [2] b0 79 [2] 9e 79 [2] a1 65 }

  condition:
    any of them
}