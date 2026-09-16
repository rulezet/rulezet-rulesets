rule TTP_XOR_WriteProcessMemory_d15c {
  strings:
    $key_d15c = { 86 2e [2] b4 0c [2] b2 39 [2] 9c 39 [2] a3 25 }

  condition:
    any of them
}