rule TTP_XOR_WriteProcessMemory_1494 {
  strings:
    $key_1494 = { 43 e6 [2] 71 c4 [2] 77 f1 [2] 59 f1 [2] 66 ed }

  condition:
    any of them
}