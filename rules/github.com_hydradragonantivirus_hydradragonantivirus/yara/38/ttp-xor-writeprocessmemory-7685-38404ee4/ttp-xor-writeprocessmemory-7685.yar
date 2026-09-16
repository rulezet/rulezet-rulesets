rule TTP_XOR_WriteProcessMemory_7685 {
  strings:
    $key_7685 = { 21 f7 [2] 13 d5 [2] 15 e0 [2] 3b e0 [2] 04 fc }

  condition:
    any of them
}