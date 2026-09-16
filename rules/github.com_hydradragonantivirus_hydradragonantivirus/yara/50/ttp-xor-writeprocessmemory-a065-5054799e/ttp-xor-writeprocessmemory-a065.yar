rule TTP_XOR_WriteProcessMemory_a065 {
  strings:
    $key_a065 = { f7 17 [2] c5 35 [2] c3 00 [2] ed 00 [2] d2 1c }

  condition:
    any of them
}