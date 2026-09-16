rule TTP_XOR_WriteProcessMemory_3f85 {
  strings:
    $key_3f85 = { 68 f7 [2] 5a d5 [2] 5c e0 [2] 72 e0 [2] 4d fc }

  condition:
    any of them
}