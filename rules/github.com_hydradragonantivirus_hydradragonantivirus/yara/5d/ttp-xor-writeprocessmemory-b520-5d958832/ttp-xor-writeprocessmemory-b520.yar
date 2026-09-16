rule TTP_XOR_WriteProcessMemory_b520 {
  strings:
    $key_b520 = { e2 52 [2] d0 70 [2] d6 45 [2] f8 45 [2] c7 59 }

  condition:
    any of them
}