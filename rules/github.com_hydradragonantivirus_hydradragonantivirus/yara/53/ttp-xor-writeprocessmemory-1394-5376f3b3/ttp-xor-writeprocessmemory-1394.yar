rule TTP_XOR_WriteProcessMemory_1394 {
  strings:
    $key_1394 = { 44 e6 [2] 76 c4 [2] 70 f1 [2] 5e f1 [2] 61 ed }

  condition:
    any of them
}