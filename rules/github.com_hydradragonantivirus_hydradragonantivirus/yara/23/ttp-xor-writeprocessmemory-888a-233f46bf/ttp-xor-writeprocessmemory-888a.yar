rule TTP_XOR_WriteProcessMemory_888a {
  strings:
    $key_888a = { df f8 [2] ed da [2] eb ef [2] c5 ef [2] fa f3 }

  condition:
    any of them
}