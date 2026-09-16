rule TTP_XOR_WriteProcessMemory_fa2b {
  strings:
    $key_fa2b = { ad 59 [2] 9f 7b [2] 99 4e [2] b7 4e [2] 88 52 }

  condition:
    any of them
}