rule TTP_XOR_WriteProcessMemory_05a7 {
  strings:
    $key_05a7 = { 52 d5 [2] 60 f7 [2] 66 c2 [2] 48 c2 [2] 77 de }

  condition:
    any of them
}