rule TTP_XOR_WriteProcessMemory_b5dc {
  strings:
    $key_b5dc = { e2 ae [2] d0 8c [2] d6 b9 [2] f8 b9 [2] c7 a5 }

  condition:
    any of them
}