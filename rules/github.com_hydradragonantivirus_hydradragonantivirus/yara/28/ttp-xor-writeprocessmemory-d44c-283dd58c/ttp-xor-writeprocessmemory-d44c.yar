rule TTP_XOR_WriteProcessMemory_d44c {
  strings:
    $key_d44c = { 83 3e [2] b1 1c [2] b7 29 [2] 99 29 [2] a6 35 }

  condition:
    any of them
}