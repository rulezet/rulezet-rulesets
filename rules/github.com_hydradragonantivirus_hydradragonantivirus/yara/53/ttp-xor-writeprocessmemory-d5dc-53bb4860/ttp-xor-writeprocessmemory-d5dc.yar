rule TTP_XOR_WriteProcessMemory_d5dc {
  strings:
    $key_d5dc = { 82 ae [2] b0 8c [2] b6 b9 [2] 98 b9 [2] a7 a5 }

  condition:
    any of them
}