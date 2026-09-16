rule TTP_XOR_WriteProcessMemory_b471 {
  strings:
    $key_b471 = { e3 03 [2] d1 21 [2] d7 14 [2] f9 14 [2] c6 08 }

  condition:
    any of them
}