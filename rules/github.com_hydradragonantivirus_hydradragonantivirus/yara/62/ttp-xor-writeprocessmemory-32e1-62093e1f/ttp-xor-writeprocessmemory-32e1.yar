rule TTP_XOR_WriteProcessMemory_32e1 {
  strings:
    $key_32e1 = { 65 93 [2] 57 b1 [2] 51 84 [2] 7f 84 [2] 40 98 }

  condition:
    any of them
}