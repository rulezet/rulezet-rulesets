rule TTP_XOR_WriteProcessMemory_fbb0 {
  strings:
    $key_fbb0 = { ac c2 [2] 9e e0 [2] 98 d5 [2] b6 d5 [2] 89 c9 }

  condition:
    any of them
}