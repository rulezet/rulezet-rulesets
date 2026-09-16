rule TTP_XOR_WriteProcessMemory_1794 {
  strings:
    $key_1794 = { 40 e6 [2] 72 c4 [2] 74 f1 [2] 5a f1 [2] 65 ed }

  condition:
    any of them
}