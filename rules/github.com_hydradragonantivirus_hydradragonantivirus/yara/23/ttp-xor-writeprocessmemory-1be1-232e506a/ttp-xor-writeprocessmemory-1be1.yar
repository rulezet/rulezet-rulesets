rule TTP_XOR_WriteProcessMemory_1be1 {
  strings:
    $key_1be1 = { 4c 93 [2] 7e b1 [2] 78 84 [2] 56 84 [2] 69 98 }

  condition:
    any of them
}