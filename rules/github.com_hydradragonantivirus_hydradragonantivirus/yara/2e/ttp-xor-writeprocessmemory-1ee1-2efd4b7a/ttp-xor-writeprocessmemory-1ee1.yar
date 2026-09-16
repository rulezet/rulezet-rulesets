rule TTP_XOR_WriteProcessMemory_1ee1 {
  strings:
    $key_1ee1 = { 49 93 [2] 7b b1 [2] 7d 84 [2] 53 84 [2] 6c 98 }

  condition:
    any of them
}