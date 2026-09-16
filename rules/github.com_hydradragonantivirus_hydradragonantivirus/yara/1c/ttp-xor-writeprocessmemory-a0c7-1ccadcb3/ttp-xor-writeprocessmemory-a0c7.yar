rule TTP_XOR_WriteProcessMemory_a0c7 {
  strings:
    $key_a0c7 = { f7 b5 [2] c5 97 [2] c3 a2 [2] ed a2 [2] d2 be }

  condition:
    any of them
}