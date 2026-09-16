rule TTP_XOR_WriteProcessMemory_a5d7 {
  strings:
    $key_a5d7 = { f2 a5 [2] c0 87 [2] c6 b2 [2] e8 b2 [2] d7 ae }

  condition:
    any of them
}