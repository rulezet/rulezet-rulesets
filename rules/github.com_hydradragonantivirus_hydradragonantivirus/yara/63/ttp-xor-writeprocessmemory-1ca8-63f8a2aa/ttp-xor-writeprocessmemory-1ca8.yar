rule TTP_XOR_WriteProcessMemory_1ca8 {
  strings:
    $key_1ca8 = { 4b da [2] 79 f8 [2] 7f cd [2] 51 cd [2] 6e d1 }

  condition:
    any of them
}