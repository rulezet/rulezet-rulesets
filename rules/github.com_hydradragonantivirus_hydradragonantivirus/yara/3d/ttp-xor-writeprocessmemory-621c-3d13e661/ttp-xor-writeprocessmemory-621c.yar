rule TTP_XOR_WriteProcessMemory_621c {
  strings:
    $key_621c = { 35 6e [2] 07 4c [2] 01 79 [2] 2f 79 [2] 10 65 }

  condition:
    any of them
}