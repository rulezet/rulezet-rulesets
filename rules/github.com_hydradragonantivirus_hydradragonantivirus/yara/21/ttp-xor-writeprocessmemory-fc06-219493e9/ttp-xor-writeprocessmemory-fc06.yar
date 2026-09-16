rule TTP_XOR_WriteProcessMemory_fc06 {
  strings:
    $key_fc06 = { ab 74 [2] 99 56 [2] 9f 63 [2] b1 63 [2] 8e 7f }

  condition:
    any of them
}