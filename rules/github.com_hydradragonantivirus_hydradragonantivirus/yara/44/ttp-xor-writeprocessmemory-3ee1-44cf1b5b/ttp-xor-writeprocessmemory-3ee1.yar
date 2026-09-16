rule TTP_XOR_WriteProcessMemory_3ee1 {
  strings:
    $key_3ee1 = { 69 93 [2] 5b b1 [2] 5d 84 [2] 73 84 [2] 4c 98 }

  condition:
    any of them
}