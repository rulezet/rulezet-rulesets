rule TTP_XOR_WriteProcessMemory_20e1 {
  strings:
    $key_20e1 = { 77 93 [2] 45 b1 [2] 43 84 [2] 6d 84 [2] 52 98 }

  condition:
    any of them
}