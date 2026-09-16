rule TTP_XOR_WriteProcessMemory_7794 {
  strings:
    $key_7794 = { 20 e6 [2] 12 c4 [2] 14 f1 [2] 3a f1 [2] 05 ed }

  condition:
    any of them
}