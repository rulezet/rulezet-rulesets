rule TTP_XOR_WriteProcessMemory_fa3c {
  strings:
    $key_fa3c = { ad 4e [2] 9f 6c [2] 99 59 [2] b7 59 [2] 88 45 }

  condition:
    any of them
}