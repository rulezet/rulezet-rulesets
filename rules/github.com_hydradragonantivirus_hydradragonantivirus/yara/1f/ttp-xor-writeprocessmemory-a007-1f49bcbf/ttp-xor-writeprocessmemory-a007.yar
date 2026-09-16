rule TTP_XOR_WriteProcessMemory_a007 {
  strings:
    $key_a007 = { f7 75 [2] c5 57 [2] c3 62 [2] ed 62 [2] d2 7e }

  condition:
    any of them
}