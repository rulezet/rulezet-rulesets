rule TTP_XOR_WriteProcessMemory_e42c {
  strings:
    $key_e42c = { b3 5e [2] 81 7c [2] 87 49 [2] a9 49 [2] 96 55 }

  condition:
    any of them
}