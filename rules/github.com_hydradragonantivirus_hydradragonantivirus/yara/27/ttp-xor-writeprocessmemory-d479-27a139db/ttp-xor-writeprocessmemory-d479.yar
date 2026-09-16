rule TTP_XOR_WriteProcessMemory_d479 {
  strings:
    $key_d479 = { 83 0b [2] b1 29 [2] b7 1c [2] 99 1c [2] a6 00 }

  condition:
    any of them
}