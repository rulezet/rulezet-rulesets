rule TTP_XOR_WriteProcessMemory_ed2e {
  strings:
    $key_ed2e = { ba 5c [2] 88 7e [2] 8e 4b [2] a0 4b [2] 9f 57 }

  condition:
    any of them
}