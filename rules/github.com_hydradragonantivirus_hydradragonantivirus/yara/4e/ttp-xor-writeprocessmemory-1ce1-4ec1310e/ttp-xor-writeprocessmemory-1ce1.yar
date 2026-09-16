rule TTP_XOR_WriteProcessMemory_1ce1 {
  strings:
    $key_1ce1 = { 4b 93 [2] 79 b1 [2] 7f 84 [2] 51 84 [2] 6e 98 }

  condition:
    any of them
}