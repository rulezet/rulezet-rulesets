rule TTP_XOR_WriteProcessMemory_6ce1 {
  strings:
    $key_6ce1 = { 3b 93 [2] 09 b1 [2] 0f 84 [2] 21 84 [2] 1e 98 }

  condition:
    any of them
}