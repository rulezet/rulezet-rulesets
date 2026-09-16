rule TTP_XOR_WriteProcessMemory_4be1 {
  strings:
    $key_4be1 = { 1c 93 [2] 2e b1 [2] 28 84 [2] 06 84 [2] 39 98 }

  condition:
    any of them
}