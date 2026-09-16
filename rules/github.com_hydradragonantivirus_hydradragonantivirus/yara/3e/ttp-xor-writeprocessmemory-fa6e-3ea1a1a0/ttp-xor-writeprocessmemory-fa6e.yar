rule TTP_XOR_WriteProcessMemory_fa6e {
  strings:
    $key_fa6e = { ad 1c [2] 9f 3e [2] 99 0b [2] b7 0b [2] 88 17 }

  condition:
    any of them
}