rule TTP_XOR_WriteProcessMemory_e5dc {
  strings:
    $key_e5dc = { b2 ae [2] 80 8c [2] 86 b9 [2] a8 b9 [2] 97 a5 }

  condition:
    any of them
}