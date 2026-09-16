rule TTP_XOR_WriteProcessMemory_fc11 {
  strings:
    $key_fc11 = { ab 63 [2] 99 41 [2] 9f 74 [2] b1 74 [2] 8e 68 }

  condition:
    any of them
}