rule TTP_XOR_WriteProcessMemory_5769 {
  strings:
    $key_5769 = { 00 1b [2] 32 39 [2] 34 0c [2] 1a 0c [2] 25 10 }

  condition:
    any of them
}