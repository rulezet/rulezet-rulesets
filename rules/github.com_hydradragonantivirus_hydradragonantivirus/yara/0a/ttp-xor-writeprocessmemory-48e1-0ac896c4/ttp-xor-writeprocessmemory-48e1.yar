rule TTP_XOR_WriteProcessMemory_48e1 {
  strings:
    $key_48e1 = { 1f 93 [2] 2d b1 [2] 2b 84 [2] 05 84 [2] 3a 98 }

  condition:
    any of them
}