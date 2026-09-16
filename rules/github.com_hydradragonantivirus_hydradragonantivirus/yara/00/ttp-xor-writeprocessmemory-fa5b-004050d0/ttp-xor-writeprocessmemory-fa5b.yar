rule TTP_XOR_WriteProcessMemory_fa5b {
  strings:
    $key_fa5b = { ad 29 [2] 9f 0b [2] 99 3e [2] b7 3e [2] 88 22 }

  condition:
    any of them
}