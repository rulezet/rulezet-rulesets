rule TTP_XOR_WriteProcessMemory_ed79 {
  strings:
    $key_ed79 = { ba 0b [2] 88 29 [2] 8e 1c [2] a0 1c [2] 9f 00 }

  condition:
    any of them
}