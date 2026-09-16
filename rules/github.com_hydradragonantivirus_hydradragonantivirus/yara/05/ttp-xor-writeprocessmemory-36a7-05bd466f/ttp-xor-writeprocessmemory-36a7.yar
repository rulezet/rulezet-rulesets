rule TTP_XOR_WriteProcessMemory_36a7 {
  strings:
    $key_36a7 = { 61 d5 [2] 53 f7 [2] 55 c2 [2] 7b c2 [2] 44 de }

  condition:
    any of them
}