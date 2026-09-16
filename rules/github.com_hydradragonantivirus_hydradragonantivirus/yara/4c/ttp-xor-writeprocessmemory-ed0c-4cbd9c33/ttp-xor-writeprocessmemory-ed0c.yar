rule TTP_XOR_WriteProcessMemory_ed0c {
  strings:
    $key_ed0c = { ba 7e [2] 88 5c [2] 8e 69 [2] a0 69 [2] 9f 75 }

  condition:
    any of them
}