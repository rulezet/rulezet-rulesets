rule TTP_XOR_WriteProcessMemory_ed39 {
  strings:
    $key_ed39 = { ba 4b [2] 88 69 [2] 8e 5c [2] a0 5c [2] 9f 40 }

  condition:
    any of them
}