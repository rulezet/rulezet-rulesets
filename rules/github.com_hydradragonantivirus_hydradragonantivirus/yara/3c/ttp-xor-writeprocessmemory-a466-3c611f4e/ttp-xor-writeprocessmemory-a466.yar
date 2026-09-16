rule TTP_XOR_WriteProcessMemory_a466 {
  strings:
    $key_a466 = { f3 14 [2] c1 36 [2] c7 03 [2] e9 03 [2] d6 1f }

  condition:
    any of them
}