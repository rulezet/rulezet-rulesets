rule TTP_XOR_WriteProcessMemory_ed3b {
  strings:
    $key_ed3b = { ba 49 [2] 88 6b [2] 8e 5e [2] a0 5e [2] 9f 42 }

  condition:
    any of them
}