rule TTP_XOR_WriteProcessMemory_e42e {
  strings:
    $key_e42e = { b3 5c [2] 81 7e [2] 87 4b [2] a9 4b [2] 96 57 }

  condition:
    any of them
}