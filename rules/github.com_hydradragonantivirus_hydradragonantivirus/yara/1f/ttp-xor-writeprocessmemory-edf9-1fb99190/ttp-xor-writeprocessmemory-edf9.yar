rule TTP_XOR_WriteProcessMemory_edf9 {
  strings:
    $key_edf9 = { ba 8b [2] 88 a9 [2] 8e 9c [2] a0 9c [2] 9f 80 }

  condition:
    any of them
}