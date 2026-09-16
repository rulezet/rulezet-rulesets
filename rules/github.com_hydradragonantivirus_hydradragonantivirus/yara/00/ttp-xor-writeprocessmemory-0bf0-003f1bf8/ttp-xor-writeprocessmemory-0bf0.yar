rule TTP_XOR_WriteProcessMemory_0bf0 {
  strings:
    $key_0bf0 = { 5c 82 [2] 6e a0 [2] 68 95 [2] 46 95 [2] 79 89 }

  condition:
    any of them
}