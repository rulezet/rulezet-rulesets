rule TTP_XOR_WriteProcessMemory_e6dc {
  strings:
    $key_e6dc = { b1 ae [2] 83 8c [2] 85 b9 [2] ab b9 [2] 94 a5 }

  condition:
    any of them
}