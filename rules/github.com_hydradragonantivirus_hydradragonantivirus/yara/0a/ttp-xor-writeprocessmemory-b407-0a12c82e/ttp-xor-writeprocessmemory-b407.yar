rule TTP_XOR_WriteProcessMemory_b407 {
  strings:
    $key_b407 = { e3 75 [2] d1 57 [2] d7 62 [2] f9 62 [2] c6 7e }

  condition:
    any of them
}