rule TTP_XOR_WriteProcessMemory_b524 {
  strings:
    $key_b524 = { e2 56 [2] d0 74 [2] d6 41 [2] f8 41 [2] c7 5d }

  condition:
    any of them
}