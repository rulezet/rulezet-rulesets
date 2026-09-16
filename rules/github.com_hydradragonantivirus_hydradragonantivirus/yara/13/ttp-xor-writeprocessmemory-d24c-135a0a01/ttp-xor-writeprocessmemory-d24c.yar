rule TTP_XOR_WriteProcessMemory_d24c {
  strings:
    $key_d24c = { 85 3e [2] b7 1c [2] b1 29 [2] 9f 29 [2] a0 35 }

  condition:
    any of them
}