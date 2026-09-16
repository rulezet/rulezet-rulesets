rule TTP_XOR_WriteProcessMemory_16a7 {
  strings:
    $key_16a7 = { 41 d5 [2] 73 f7 [2] 75 c2 [2] 5b c2 [2] 64 de }

  condition:
    any of them
}