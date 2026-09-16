rule TTP_XOR_WriteProcessMemory_fc64 {
  strings:
    $key_fc64 = { ab 16 [2] 99 34 [2] 9f 01 [2] b1 01 [2] 8e 1d }

  condition:
    any of them
}