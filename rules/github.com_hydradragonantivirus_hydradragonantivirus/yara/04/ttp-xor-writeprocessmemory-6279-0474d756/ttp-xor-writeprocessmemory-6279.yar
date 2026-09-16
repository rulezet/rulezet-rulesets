rule TTP_XOR_WriteProcessMemory_6279 {
  strings:
    $key_6279 = { 35 0b [2] 07 29 [2] 01 1c [2] 2f 1c [2] 10 00 }

  condition:
    any of them
}