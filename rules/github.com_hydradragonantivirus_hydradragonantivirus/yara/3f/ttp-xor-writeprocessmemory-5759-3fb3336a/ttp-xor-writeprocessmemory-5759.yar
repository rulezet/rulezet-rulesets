rule TTP_XOR_WriteProcessMemory_5759 {
  strings:
    $key_5759 = { 00 2b [2] 32 09 [2] 34 3c [2] 1a 3c [2] 25 20 }

  condition:
    any of them
}