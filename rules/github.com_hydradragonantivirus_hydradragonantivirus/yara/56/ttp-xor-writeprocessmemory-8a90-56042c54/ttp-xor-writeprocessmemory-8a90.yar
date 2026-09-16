rule TTP_XOR_WriteProcessMemory_8a90 {
  strings:
    $key_8a90 = { dd e2 [2] ef c0 [2] e9 f5 [2] c7 f5 [2] f8 e9 }

  condition:
    any of them
}