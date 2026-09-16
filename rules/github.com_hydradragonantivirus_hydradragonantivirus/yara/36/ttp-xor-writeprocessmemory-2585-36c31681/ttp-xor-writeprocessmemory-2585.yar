rule TTP_XOR_WriteProcessMemory_2585 {
  strings:
    $key_2585 = { 72 f7 [2] 40 d5 [2] 46 e0 [2] 68 e0 [2] 57 fc }

  condition:
    any of them
}