rule TTP_XOR_WriteProcessMemory_a6dc {
  strings:
    $key_a6dc = { f1 ae [2] c3 8c [2] c5 b9 [2] eb b9 [2] d4 a5 }

  condition:
    any of them
}