rule TTP_XOR_WriteProcessMemory_16e1 {
  strings:
    $key_16e1 = { 41 93 [2] 73 b1 [2] 75 84 [2] 5b 84 [2] 64 98 }

  condition:
    any of them
}