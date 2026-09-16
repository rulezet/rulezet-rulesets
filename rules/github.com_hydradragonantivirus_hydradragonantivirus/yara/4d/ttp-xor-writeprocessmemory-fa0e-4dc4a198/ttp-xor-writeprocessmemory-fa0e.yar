rule TTP_XOR_WriteProcessMemory_fa0e {
  strings:
    $key_fa0e = { ad 7c [2] 9f 5e [2] 99 6b [2] b7 6b [2] 88 77 }

  condition:
    any of them
}