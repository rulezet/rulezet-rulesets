rule TTP_XOR_WriteProcessMemory_f3ac {
  strings:
    $key_f3ac = { a4 de [2] 96 fc [2] 90 c9 [2] be c9 [2] 81 d5 }

  condition:
    any of them
}