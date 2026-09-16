rule TTP_XOR_WriteProcessMemory_12e1 {
  strings:
    $key_12e1 = { 45 93 [2] 77 b1 [2] 71 84 [2] 5f 84 [2] 60 98 }

  condition:
    any of them
}