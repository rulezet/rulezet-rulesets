rule TTP_XOR_WriteProcessMemory_a420 {
  strings:
    $key_a420 = { f3 52 [2] c1 70 [2] c7 45 [2] e9 45 [2] d6 59 }

  condition:
    any of them
}