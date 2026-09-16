rule TTP_XOR_WriteProcessMemory_3685 {
  strings:
    $key_3685 = { 61 f7 [2] 53 d5 [2] 55 e0 [2] 7b e0 [2] 44 fc }

  condition:
    any of them
}