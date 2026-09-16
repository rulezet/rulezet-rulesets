rule TTP_XOR_WriteProcessMemory_78e1 {
  strings:
    $key_78e1 = { 2f 93 [2] 1d b1 [2] 1b 84 [2] 35 84 [2] 0a 98 }

  condition:
    any of them
}