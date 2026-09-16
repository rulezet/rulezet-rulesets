rule TTP_XOR_WriteProcessMemory_d42c {
  strings:
    $key_d42c = { 83 5e [2] b1 7c [2] b7 49 [2] 99 49 [2] a6 55 }

  condition:
    any of them
}