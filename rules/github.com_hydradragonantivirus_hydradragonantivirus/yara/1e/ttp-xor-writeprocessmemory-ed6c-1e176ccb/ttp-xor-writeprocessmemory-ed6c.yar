rule TTP_XOR_WriteProcessMemory_ed6c {
  strings:
    $key_ed6c = { ba 1e [2] 88 3c [2] 8e 09 [2] a0 09 [2] 9f 15 }

  condition:
    any of them
}