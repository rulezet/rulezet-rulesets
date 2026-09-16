rule TTP_XOR_WriteProcessMemory_58e1 {
  strings:
    $key_58e1 = { 0f 93 [2] 3d b1 [2] 3b 84 [2] 15 84 [2] 2a 98 }

  condition:
    any of them
}