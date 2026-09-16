rule TTP_XOR_WriteProcessMemory_ed59 {
  strings:
    $key_ed59 = { ba 2b [2] 88 09 [2] 8e 3c [2] a0 3c [2] 9f 20 }

  condition:
    any of them
}