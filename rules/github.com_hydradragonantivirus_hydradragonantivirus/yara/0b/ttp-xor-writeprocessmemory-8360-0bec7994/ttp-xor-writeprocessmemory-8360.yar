rule TTP_XOR_WriteProcessMemory_8360 {
  strings:
    $key_8360 = { d4 12 [2] e6 30 [2] e0 05 [2] ce 05 [2] f1 19 }

  condition:
    any of them
}