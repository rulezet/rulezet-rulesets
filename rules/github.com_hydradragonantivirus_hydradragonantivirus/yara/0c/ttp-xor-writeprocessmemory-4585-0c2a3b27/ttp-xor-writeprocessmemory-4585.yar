rule TTP_XOR_WriteProcessMemory_4585 {
  strings:
    $key_4585 = { 12 f7 [2] 20 d5 [2] 26 e0 [2] 08 e0 [2] 37 fc }

  condition:
    any of them
}