rule TTP_XOR_WriteProcessMemory_fc60 {
  strings:
    $key_fc60 = { ab 12 [2] 99 30 [2] 9f 05 [2] b1 05 [2] 8e 19 }

  condition:
    any of them
}