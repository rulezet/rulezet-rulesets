rule TTP_XOR_WriteProcessMemory_b409 {
  strings:
    $key_b409 = { e3 7b [2] d1 59 [2] d7 6c [2] f9 6c [2] c6 70 }

  condition:
    any of them
}