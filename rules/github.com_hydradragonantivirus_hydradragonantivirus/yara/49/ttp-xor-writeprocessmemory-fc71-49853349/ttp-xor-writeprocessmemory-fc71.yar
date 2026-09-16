rule TTP_XOR_WriteProcessMemory_fc71 {
  strings:
    $key_fc71 = { ab 03 [2] 99 21 [2] 9f 14 [2] b1 14 [2] 8e 08 }

  condition:
    any of them
}