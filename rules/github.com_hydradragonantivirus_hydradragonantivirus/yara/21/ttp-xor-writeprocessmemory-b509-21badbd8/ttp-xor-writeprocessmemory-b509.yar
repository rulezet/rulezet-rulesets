rule TTP_XOR_WriteProcessMemory_b509 {
  strings:
    $key_b509 = { e2 7b [2] d0 59 [2] d6 6c [2] f8 6c [2] c7 70 }

  condition:
    any of them
}