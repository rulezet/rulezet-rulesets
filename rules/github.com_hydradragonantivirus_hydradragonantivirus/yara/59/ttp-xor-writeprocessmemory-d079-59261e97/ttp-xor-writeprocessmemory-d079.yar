rule TTP_XOR_WriteProcessMemory_d079 {
  strings:
    $key_d079 = { 87 0b [2] b5 29 [2] b3 1c [2] 9d 1c [2] a2 00 }

  condition:
    any of them
}