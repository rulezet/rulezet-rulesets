rule TTP_XOR_WriteProcessMemory_36dc {
  strings:
    $key_36dc = { 61 ae [2] 53 8c [2] 55 b9 [2] 7b b9 [2] 44 a5 }

  condition:
    any of them
}