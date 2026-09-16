rule TTP_XOR_WriteProcessMemory_3fe1 {
  strings:
    $key_3fe1 = { 68 93 [2] 5a b1 [2] 5c 84 [2] 72 84 [2] 4d 98 }

  condition:
    any of them
}