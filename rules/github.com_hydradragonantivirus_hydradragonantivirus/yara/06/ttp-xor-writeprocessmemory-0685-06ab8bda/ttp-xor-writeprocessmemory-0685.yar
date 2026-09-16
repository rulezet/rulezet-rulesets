rule TTP_XOR_WriteProcessMemory_0685 {
  strings:
    $key_0685 = { 51 f7 [2] 63 d5 [2] 65 e0 [2] 4b e0 [2] 74 fc }

  condition:
    any of them
}