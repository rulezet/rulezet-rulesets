rule TTP_XOR_WriteProcessMemory_4a92 {
  strings:
    $key_4a92 = { 1d e0 [2] 2f c2 [2] 29 f7 [2] 07 f7 [2] 38 eb }

  condition:
    any of them
}