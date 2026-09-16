rule TTP_XOR_WriteProcessMemory_c3dc {
  strings:
    $key_c3dc = { 94 ae [2] a6 8c [2] a0 b9 [2] 8e b9 [2] b1 a5 }

  condition:
    any of them
}