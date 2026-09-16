rule TTP_XOR_WriteProcessMemory_2ee1 {
  strings:
    $key_2ee1 = { 79 93 [2] 4b b1 [2] 4d 84 [2] 63 84 [2] 5c 98 }

  condition:
    any of them
}