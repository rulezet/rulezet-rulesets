rule TTP_XOR_WriteProcessMemory_0ca8 {
  strings:
    $key_0ca8 = { 5b da [2] 69 f8 [2] 6f cd [2] 41 cd [2] 7e d1 }

  condition:
    any of them
}