rule TTP_XOR_WriteProcessMemory_41e1 {
  strings:
    $key_41e1 = { 16 93 [2] 24 b1 [2] 22 84 [2] 0c 84 [2] 33 98 }

  condition:
    any of them
}