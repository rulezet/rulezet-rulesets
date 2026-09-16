rule TTP_XOR_WriteProcessMemory_e2dc {
  strings:
    $key_e2dc = { b5 ae [2] 87 8c [2] 81 b9 [2] af b9 [2] 90 a5 }

  condition:
    any of them
}