rule TTP_XOR_WriteProcessMemory_05e1 {
  strings:
    $key_05e1 = { 52 93 [2] 60 b1 [2] 66 84 [2] 48 84 [2] 77 98 }

  condition:
    any of them
}