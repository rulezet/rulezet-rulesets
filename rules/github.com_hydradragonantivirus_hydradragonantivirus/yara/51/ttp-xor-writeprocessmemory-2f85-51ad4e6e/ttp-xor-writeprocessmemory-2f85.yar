rule TTP_XOR_WriteProcessMemory_2f85 {
  strings:
    $key_2f85 = { 78 f7 [2] 4a d5 [2] 4c e0 [2] 62 e0 [2] 5d fc }

  condition:
    any of them
}