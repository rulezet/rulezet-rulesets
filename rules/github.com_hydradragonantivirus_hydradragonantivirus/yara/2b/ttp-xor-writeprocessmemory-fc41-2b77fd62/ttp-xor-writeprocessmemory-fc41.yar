rule TTP_XOR_WriteProcessMemory_fc41 {
  strings:
    $key_fc41 = { ab 33 [2] 99 11 [2] 9f 24 [2] b1 24 [2] 8e 38 }

  condition:
    any of them
}