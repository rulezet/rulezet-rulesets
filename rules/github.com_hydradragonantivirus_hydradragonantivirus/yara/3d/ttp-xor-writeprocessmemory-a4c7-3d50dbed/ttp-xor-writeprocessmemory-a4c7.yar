rule TTP_XOR_WriteProcessMemory_a4c7 {
  strings:
    $key_a4c7 = { f3 b5 [2] c1 97 [2] c7 a2 [2] e9 a2 [2] d6 be }

  condition:
    any of them
}