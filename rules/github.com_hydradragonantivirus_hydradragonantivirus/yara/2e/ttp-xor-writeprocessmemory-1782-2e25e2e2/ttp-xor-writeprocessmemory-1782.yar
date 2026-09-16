rule TTP_XOR_WriteProcessMemory_1782 {
  strings:
    $key_1782 = { 40 f0 [2] 72 d2 [2] 74 e7 [2] 5a e7 [2] 65 fb }

  condition:
    any of them
}