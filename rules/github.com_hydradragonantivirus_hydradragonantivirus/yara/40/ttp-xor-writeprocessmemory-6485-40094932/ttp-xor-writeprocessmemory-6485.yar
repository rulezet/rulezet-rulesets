rule TTP_XOR_WriteProcessMemory_6485 {
  strings:
    $key_6485 = { 33 f7 [2] 01 d5 [2] 07 e0 [2] 29 e0 [2] 16 fc }

  condition:
    any of them
}