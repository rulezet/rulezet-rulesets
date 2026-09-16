rule TTP_XOR_WriteProcessMemory_fc53 {
  strings:
    $key_fc53 = { ab 21 [2] 99 03 [2] 9f 36 [2] b1 36 [2] 8e 2a }

  condition:
    any of them
}