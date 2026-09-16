rule TTP_XOR_WriteProcessMemory_8880 {
  strings:
    $key_8880 = { df f2 [2] ed d0 [2] eb e5 [2] c5 e5 [2] fa f9 }

  condition:
    any of them
}