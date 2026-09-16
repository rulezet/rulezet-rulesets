rule TTP_XOR_WriteProcessMemory_fc21 {
  strings:
    $key_fc21 = { ab 53 [2] 99 71 [2] 9f 44 [2] b1 44 [2] 8e 58 }

  condition:
    any of them
}