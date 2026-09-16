rule TTP_XOR_WriteProcessMemory_1fe1 {
  strings:
    $key_1fe1 = { 48 93 [2] 7a b1 [2] 7c 84 [2] 52 84 [2] 6d 98 }

  condition:
    any of them
}