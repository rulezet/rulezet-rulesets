rule TTP_XOR_WriteProcessMemory_b1d7 {
  strings:
    $key_b1d7 = { e6 a5 [2] d4 87 [2] d2 b2 [2] fc b2 [2] c3 ae }

  condition:
    any of them
}