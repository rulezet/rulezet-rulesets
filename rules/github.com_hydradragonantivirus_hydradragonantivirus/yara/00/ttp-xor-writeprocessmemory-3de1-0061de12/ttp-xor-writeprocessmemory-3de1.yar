rule TTP_XOR_WriteProcessMemory_3de1 {
  strings:
    $key_3de1 = { 6a 93 [2] 58 b1 [2] 5e 84 [2] 70 84 [2] 4f 98 }

  condition:
    any of them
}