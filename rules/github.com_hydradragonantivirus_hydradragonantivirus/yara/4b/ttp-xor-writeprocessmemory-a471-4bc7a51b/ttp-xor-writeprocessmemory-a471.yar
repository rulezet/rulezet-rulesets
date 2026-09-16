rule TTP_XOR_WriteProcessMemory_a471 {
  strings:
    $key_a471 = { f3 03 [2] c1 21 [2] c7 14 [2] e9 14 [2] d6 08 }

  condition:
    any of them
}