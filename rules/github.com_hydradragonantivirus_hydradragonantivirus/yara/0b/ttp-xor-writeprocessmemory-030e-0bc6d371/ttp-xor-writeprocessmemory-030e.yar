rule TTP_XOR_WriteProcessMemory_030e {
  strings:
    $key_030e = { 54 7c [2] 66 5e [2] 60 6b [2] 4e 6b [2] 71 77 }

  condition:
    any of them
}