rule TTP_XOR_WriteProcessMemory_b564 {
  strings:
    $key_b564 = { e2 16 [2] d0 34 [2] d6 01 [2] f8 01 [2] c7 1d }

  condition:
    any of them
}