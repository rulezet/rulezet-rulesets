rule TTP_XOR_WriteProcessMemory_1785 {
  strings:
    $key_1785 = { 40 f7 [2] 72 d5 [2] 74 e0 [2] 5a e0 [2] 65 fc }

  condition:
    any of them
}