rule TTP_XOR_WriteProcessMemory_ed7c {
  strings:
    $key_ed7c = { ba 0e [2] 88 2c [2] 8e 19 [2] a0 19 [2] 9f 05 }

  condition:
    any of them
}