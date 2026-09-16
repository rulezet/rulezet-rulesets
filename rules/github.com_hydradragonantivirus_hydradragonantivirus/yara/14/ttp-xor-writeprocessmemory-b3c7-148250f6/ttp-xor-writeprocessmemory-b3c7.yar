rule TTP_XOR_WriteProcessMemory_b3c7 {
  strings:
    $key_b3c7 = { e4 b5 [2] d6 97 [2] d0 a2 [2] fe a2 [2] c1 be }

  condition:
    any of them
}