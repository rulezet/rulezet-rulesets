rule TTP_XOR_WriteProcessMemory_8881 {
  strings:
    $key_8881 = { df f3 [2] ed d1 [2] eb e4 [2] c5 e4 [2] fa f8 }

  condition:
    any of them
}