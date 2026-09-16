rule TTP_XOR_WriteProcessMemory_12dc {
  strings:
    $key_12dc = { 45 ae [2] 77 8c [2] 71 b9 [2] 5f b9 [2] 60 a5 }

  condition:
    any of them
}