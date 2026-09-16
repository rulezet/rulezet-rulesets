rule TTP_XOR_WriteProcessMemory_ed2c {
  strings:
    $key_ed2c = { ba 5e [2] 88 7c [2] 8e 49 [2] a0 49 [2] 9f 55 }

  condition:
    any of them
}