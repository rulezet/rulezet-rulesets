rule TTP_XOR_WriteProcessMemory_acb7 {
  strings:
    $key_acb7 = { fb c5 [2] c9 e7 [2] cf d2 [2] e1 d2 [2] de ce }

  condition:
    any of them
}