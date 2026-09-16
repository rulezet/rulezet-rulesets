rule TTP_XOR_WriteProcessMemory_a4d7 {
  strings:
    $key_a4d7 = { f3 a5 [2] c1 87 [2] c7 b2 [2] e9 b2 [2] d6 ae }

  condition:
    any of them
}