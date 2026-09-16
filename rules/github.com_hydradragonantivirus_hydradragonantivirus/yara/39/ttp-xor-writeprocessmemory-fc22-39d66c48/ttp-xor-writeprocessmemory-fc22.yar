rule TTP_XOR_WriteProcessMemory_fc22 {
  strings:
    $key_fc22 = { ab 50 [2] 99 72 [2] 9f 47 [2] b1 47 [2] 8e 5b }

  condition:
    any of them
}