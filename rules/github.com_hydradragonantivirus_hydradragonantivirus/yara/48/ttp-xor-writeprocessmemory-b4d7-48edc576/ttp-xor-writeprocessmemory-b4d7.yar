rule TTP_XOR_WriteProcessMemory_b4d7 {
  strings:
    $key_b4d7 = { e3 a5 [2] d1 87 [2] d7 b2 [2] f9 b2 [2] c6 ae }

  condition:
    any of them
}