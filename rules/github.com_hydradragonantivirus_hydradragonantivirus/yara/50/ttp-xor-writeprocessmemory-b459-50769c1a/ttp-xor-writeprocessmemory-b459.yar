rule TTP_XOR_WriteProcessMemory_b459 {
  strings:
    $key_b459 = { e3 2b [2] d1 09 [2] d7 3c [2] f9 3c [2] c6 20 }

  condition:
    any of them
}