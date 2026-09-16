rule TTP_XOR_WriteProcessMemory_ed1e {
  strings:
    $key_ed1e = { ba 6c [2] 88 4e [2] 8e 7b [2] a0 7b [2] 9f 67 }

  condition:
    any of them
}