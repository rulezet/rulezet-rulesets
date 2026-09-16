rule TTP_XOR_WriteProcessMemory_8a94 {
  strings:
    $key_8a94 = { dd e6 [2] ef c4 [2] e9 f1 [2] c7 f1 [2] f8 ed }

  condition:
    any of them
}