rule TTP_XOR_WriteProcessMemory_4ca8 {
  strings:
    $key_4ca8 = { 1b da [2] 29 f8 [2] 2f cd [2] 01 cd [2] 3e d1 }

  condition:
    any of them
}