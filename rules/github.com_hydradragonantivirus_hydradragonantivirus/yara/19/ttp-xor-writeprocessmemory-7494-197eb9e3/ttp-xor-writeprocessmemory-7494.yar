rule TTP_XOR_WriteProcessMemory_7494 {
  strings:
    $key_7494 = { 23 e6 [2] 11 c4 [2] 17 f1 [2] 39 f1 [2] 06 ed }

  condition:
    any of them
}