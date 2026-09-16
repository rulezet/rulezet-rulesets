rule TTP_XOR_WriteProcessMemory_4594 {
  strings:
    $key_4594 = { 12 e6 [2] 20 c4 [2] 26 f1 [2] 08 f1 [2] 37 ed }

  condition:
    any of them
}