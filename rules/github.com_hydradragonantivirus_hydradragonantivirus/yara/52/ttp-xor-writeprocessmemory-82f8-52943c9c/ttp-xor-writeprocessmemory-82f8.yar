rule TTP_XOR_WriteProcessMemory_82f8 {
  strings:
    $key_82f8 = { d5 8a [2] e7 a8 [2] e1 9d [2] cf 9d [2] f0 81 }

  condition:
    any of them
}