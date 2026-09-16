rule TTP_XOR_WriteProcessMemory_e45c {
  strings:
    $key_e45c = { b3 2e [2] 81 0c [2] 87 39 [2] a9 39 [2] 96 25 }

  condition:
    any of them
}