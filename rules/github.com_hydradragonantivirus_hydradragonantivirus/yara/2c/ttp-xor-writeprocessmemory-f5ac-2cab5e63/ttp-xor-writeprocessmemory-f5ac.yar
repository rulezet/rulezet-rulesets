rule TTP_XOR_WriteProcessMemory_f5ac {
  strings:
    $key_f5ac = { a2 de [2] 90 fc [2] 96 c9 [2] b8 c9 [2] 87 d5 }

  condition:
    any of them
}