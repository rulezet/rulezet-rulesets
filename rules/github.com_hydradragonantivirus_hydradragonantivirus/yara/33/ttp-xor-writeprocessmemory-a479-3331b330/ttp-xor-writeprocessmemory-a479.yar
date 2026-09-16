rule TTP_XOR_WriteProcessMemory_a479 {
  strings:
    $key_a479 = { f3 0b [2] c1 29 [2] c7 1c [2] e9 1c [2] d6 00 }

  condition:
    any of them
}