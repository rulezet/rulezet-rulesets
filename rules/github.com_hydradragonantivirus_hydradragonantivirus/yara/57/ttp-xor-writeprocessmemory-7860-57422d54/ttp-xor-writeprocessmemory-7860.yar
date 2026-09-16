rule TTP_XOR_WriteProcessMemory_7860 {
  strings:
    $key_7860 = { 2f 12 [2] 1d 30 [2] 1b 05 [2] 35 05 [2] 0a 19 }

  condition:
    any of them
}