rule TTP_XOR_WriteProcessMemory_32dc {
  strings:
    $key_32dc = { 65 ae [2] 57 8c [2] 51 b9 [2] 7f b9 [2] 40 a5 }

  condition:
    any of them
}