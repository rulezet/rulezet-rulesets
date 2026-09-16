rule TTP_XOR_WriteProcessMemory_fc00 {
  strings:
    $key_fc00 = { ab 72 [2] 99 50 [2] 9f 65 [2] b1 65 [2] 8e 79 }

  condition:
    any of them
}