rule TTP_XOR_WriteProcessMemory_fc02 {
  strings:
    $key_fc02 = { ab 70 [2] 99 52 [2] 9f 67 [2] b1 67 [2] 8e 7b }

  condition:
    any of them
}