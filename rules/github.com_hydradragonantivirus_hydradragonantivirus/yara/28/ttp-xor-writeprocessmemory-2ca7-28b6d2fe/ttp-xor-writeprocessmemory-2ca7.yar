rule TTP_XOR_WriteProcessMemory_2ca7 {
  strings:
    $key_2ca7 = { 7b d5 [2] 49 f7 [2] 4f c2 [2] 61 c2 [2] 5e de }

  condition:
    any of them
}