rule TTP_XOR_WriteProcessMemory_6539 {
  strings:
    $key_6539 = { 32 4b [2] 00 69 [2] 06 5c [2] 28 5c [2] 17 40 }

  condition:
    any of them
}