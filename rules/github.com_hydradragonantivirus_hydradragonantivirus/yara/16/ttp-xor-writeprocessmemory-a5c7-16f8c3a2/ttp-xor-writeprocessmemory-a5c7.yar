rule TTP_XOR_WriteProcessMemory_a5c7 {
  strings:
    $key_a5c7 = { f2 b5 [2] c0 97 [2] c6 a2 [2] e8 a2 [2] d7 be }

  condition:
    any of them
}