rule TTP_XOR_WriteProcessMemory_fc56 {
  strings:
    $key_fc56 = { ab 24 [2] 99 06 [2] 9f 33 [2] b1 33 [2] 8e 2f }

  condition:
    any of them
}