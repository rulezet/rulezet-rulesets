rule TTP_XOR_WriteProcessMemory_4ca7 {
  strings:
    $key_4ca7 = { 1b d5 [2] 29 f7 [2] 2f c2 [2] 01 c2 [2] 3e de }

  condition:
    any of them
}