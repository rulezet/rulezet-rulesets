rule TTP_XOR_WriteProcessMemory_ed30 {
  strings:
    $key_ed30 = { ba 42 [2] 88 60 [2] 8e 55 [2] a0 55 [2] 9f 49 }

  condition:
    any of them
}