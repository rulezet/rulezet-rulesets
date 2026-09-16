rule TTP_XOR_WriteProcessMemory_3394 {
  strings:
    $key_3394 = { 64 e6 [2] 56 c4 [2] 50 f1 [2] 7e f1 [2] 41 ed }

  condition:
    any of them
}