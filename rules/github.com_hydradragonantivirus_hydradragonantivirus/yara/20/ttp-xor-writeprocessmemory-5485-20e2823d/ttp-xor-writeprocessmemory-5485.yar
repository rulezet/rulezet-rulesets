rule TTP_XOR_WriteProcessMemory_5485 {
  strings:
    $key_5485 = { 03 f7 [2] 31 d5 [2] 37 e0 [2] 19 e0 [2] 26 fc }

  condition:
    any of them
}