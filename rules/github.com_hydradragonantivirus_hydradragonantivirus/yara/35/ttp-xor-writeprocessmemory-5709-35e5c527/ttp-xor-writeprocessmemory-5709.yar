rule TTP_XOR_WriteProcessMemory_5709 {
  strings:
    $key_5709 = { 00 7b [2] 32 59 [2] 34 6c [2] 1a 6c [2] 25 70 }

  condition:
    any of them
}