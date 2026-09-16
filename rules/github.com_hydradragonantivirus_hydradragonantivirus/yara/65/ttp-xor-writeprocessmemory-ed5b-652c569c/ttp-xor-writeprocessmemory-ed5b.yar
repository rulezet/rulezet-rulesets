rule TTP_XOR_WriteProcessMemory_ed5b {
  strings:
    $key_ed5b = { ba 29 [2] 88 0b [2] 8e 3e [2] a0 3e [2] 9f 22 }

  condition:
    any of them
}