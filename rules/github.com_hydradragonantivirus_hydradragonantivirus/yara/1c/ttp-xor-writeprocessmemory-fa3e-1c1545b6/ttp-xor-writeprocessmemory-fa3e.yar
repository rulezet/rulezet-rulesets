rule TTP_XOR_WriteProcessMemory_fa3e {
  strings:
    $key_fa3e = { ad 4c [2] 9f 6e [2] 99 5b [2] b7 5b [2] 88 47 }

  condition:
    any of them
}