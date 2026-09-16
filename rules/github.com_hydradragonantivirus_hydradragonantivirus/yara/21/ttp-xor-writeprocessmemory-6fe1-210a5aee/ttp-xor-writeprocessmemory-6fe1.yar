rule TTP_XOR_WriteProcessMemory_6fe1 {
  strings:
    $key_6fe1 = { 38 93 [2] 0a b1 [2] 0c 84 [2] 22 84 [2] 1d 98 }

  condition:
    any of them
}