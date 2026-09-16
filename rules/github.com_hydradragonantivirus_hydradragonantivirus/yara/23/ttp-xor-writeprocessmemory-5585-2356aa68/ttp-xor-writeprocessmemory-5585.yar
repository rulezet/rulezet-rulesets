rule TTP_XOR_WriteProcessMemory_5585 {
  strings:
    $key_5585 = { 02 f7 [2] 30 d5 [2] 36 e0 [2] 18 e0 [2] 27 fc }

  condition:
    any of them
}