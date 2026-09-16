rule TTP_XOR_WriteProcessMemory_e46c {
  strings:
    $key_e46c = { b3 1e [2] 81 3c [2] 87 09 [2] a9 09 [2] 96 15 }

  condition:
    any of them
}