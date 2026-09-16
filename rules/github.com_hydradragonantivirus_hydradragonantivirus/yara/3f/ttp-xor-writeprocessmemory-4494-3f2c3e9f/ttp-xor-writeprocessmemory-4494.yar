rule TTP_XOR_WriteProcessMemory_4494 {
  strings:
    $key_4494 = { 13 e6 [2] 21 c4 [2] 27 f1 [2] 09 f1 [2] 36 ed }

  condition:
    any of them
}