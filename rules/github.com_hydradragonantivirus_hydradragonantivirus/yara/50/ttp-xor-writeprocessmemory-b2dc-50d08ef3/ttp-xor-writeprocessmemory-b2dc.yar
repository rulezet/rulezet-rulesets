rule TTP_XOR_WriteProcessMemory_b2dc {
  strings:
    $key_b2dc = { e5 ae [2] d7 8c [2] d1 b9 [2] ff b9 [2] c0 a5 }

  condition:
    any of them
}