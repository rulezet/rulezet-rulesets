rule TTP_XOR_WriteProcessMemory_5129 {
  strings:
    $key_5129 = { 06 5b [2] 34 79 [2] 32 4c [2] 1c 4c [2] 23 50 }

  condition:
    any of them
}