rule TTP_XOR_WriteProcessMemory_aab2 {
  strings:
    $key_aab2 = { fd c0 [2] cf e2 [2] c9 d7 [2] e7 d7 [2] d8 cb }

  condition:
    any of them
}