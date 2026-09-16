rule TTP_XOR_WriteProcessMemory_5fe1 {
  strings:
    $key_5fe1 = { 08 93 [2] 3a b1 [2] 3c 84 [2] 12 84 [2] 2d 98 }

  condition:
    any of them
}