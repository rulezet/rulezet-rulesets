rule TTP_XOR_WriteProcessMemory_b4dc {
  strings:
    $key_b4dc = { e3 ae [2] d1 8c [2] d7 b9 [2] f9 b9 [2] c6 a5 }

  condition:
    any of them
}