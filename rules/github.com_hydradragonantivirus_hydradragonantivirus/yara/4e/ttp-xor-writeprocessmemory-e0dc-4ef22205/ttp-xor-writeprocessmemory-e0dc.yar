rule TTP_XOR_WriteProcessMemory_e0dc {
  strings:
    $key_e0dc = { b7 ae [2] 85 8c [2] 83 b9 [2] ad b9 [2] 92 a5 }

  condition:
    any of them
}