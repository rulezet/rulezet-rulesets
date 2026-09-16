rule TTP_XOR_WriteProcessMemory_0be1 {
  strings:
    $key_0be1 = { 5c 93 [2] 6e b1 [2] 68 84 [2] 46 84 [2] 79 98 }

  condition:
    any of them
}