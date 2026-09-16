rule TTP_XOR_WriteProcessMemory_42dc {
  strings:
    $key_42dc = { 15 ae [2] 27 8c [2] 21 b9 [2] 0f b9 [2] 30 a5 }

  condition:
    any of them
}