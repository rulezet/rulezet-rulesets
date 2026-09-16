rule TTP_XOR_WriteProcessMemory_6394 {
  strings:
    $key_6394 = { 34 e6 [2] 06 c4 [2] 00 f1 [2] 2e f1 [2] 11 ed }

  condition:
    any of them
}