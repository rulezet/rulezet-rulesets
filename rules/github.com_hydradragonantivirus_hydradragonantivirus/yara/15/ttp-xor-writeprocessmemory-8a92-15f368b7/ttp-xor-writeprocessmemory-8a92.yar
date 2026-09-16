rule TTP_XOR_WriteProcessMemory_8a92 {
  strings:
    $key_8a92 = { dd e0 [2] ef c2 [2] e9 f7 [2] c7 f7 [2] f8 eb }

  condition:
    any of them
}