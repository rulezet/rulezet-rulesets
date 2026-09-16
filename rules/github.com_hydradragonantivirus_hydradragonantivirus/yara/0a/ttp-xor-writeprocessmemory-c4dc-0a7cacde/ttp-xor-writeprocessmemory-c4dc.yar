rule TTP_XOR_WriteProcessMemory_c4dc {
  strings:
    $key_c4dc = { 93 ae [2] a1 8c [2] a7 b9 [2] 89 b9 [2] b6 a5 }

  condition:
    any of them
}