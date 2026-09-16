rule TTP_XOR_WriteProcessMemory_ed19 {
  strings:
    $key_ed19 = { ba 6b [2] 88 49 [2] 8e 7c [2] a0 7c [2] 9f 60 }

  condition:
    any of them
}