rule TTP_XOR_WriteProcessMemory_fc36 {
  strings:
    $key_fc36 = { ab 44 [2] 99 66 [2] 9f 53 [2] b1 53 [2] 8e 4f }

  condition:
    any of them
}