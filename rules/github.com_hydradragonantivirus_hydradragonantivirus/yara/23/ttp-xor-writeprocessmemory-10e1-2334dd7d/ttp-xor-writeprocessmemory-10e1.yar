rule TTP_XOR_WriteProcessMemory_10e1 {
  strings:
    $key_10e1 = { 47 93 [2] 75 b1 [2] 73 84 [2] 5d 84 [2] 62 98 }

  condition:
    any of them
}