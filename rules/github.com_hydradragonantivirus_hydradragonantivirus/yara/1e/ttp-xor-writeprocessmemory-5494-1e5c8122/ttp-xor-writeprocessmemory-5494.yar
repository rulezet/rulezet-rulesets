rule TTP_XOR_WriteProcessMemory_5494 {
  strings:
    $key_5494 = { 03 e6 [2] 31 c4 [2] 37 f1 [2] 19 f1 [2] 26 ed }

  condition:
    any of them
}