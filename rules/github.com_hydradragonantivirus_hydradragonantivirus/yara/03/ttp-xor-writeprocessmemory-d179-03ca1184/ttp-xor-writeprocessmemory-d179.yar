rule TTP_XOR_WriteProcessMemory_d179 {
  strings:
    $key_d179 = { 86 0b [2] b4 29 [2] b2 1c [2] 9c 1c [2] a3 00 }

  condition:
    any of them
}