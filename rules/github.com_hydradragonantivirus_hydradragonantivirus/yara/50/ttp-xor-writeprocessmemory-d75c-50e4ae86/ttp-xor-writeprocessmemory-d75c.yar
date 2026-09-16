rule TTP_XOR_WriteProcessMemory_d75c {
  strings:
    $key_d75c = { 80 2e [2] b2 0c [2] b4 39 [2] 9a 39 [2] a5 25 }

  condition:
    any of them
}