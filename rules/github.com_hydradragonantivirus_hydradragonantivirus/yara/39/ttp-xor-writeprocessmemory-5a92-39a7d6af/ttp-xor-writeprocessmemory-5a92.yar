rule TTP_XOR_WriteProcessMemory_5a92 {
  strings:
    $key_5a92 = { 0d e0 [2] 3f c2 [2] 39 f7 [2] 17 f7 [2] 28 eb }

  condition:
    any of them
}