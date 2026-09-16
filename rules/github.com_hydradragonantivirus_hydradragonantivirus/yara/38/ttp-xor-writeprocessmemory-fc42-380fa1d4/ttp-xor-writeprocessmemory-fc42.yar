rule TTP_XOR_WriteProcessMemory_fc42 {
  strings:
    $key_fc42 = { ab 30 [2] 99 12 [2] 9f 27 [2] b1 27 [2] 8e 3b }

  condition:
    any of them
}