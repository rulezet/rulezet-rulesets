rule TTP_XOR_WriteProcessMemory_fc63 {
  strings:
    $key_fc63 = { ab 11 [2] 99 33 [2] 9f 06 [2] b1 06 [2] 8e 1a }

  condition:
    any of them
}