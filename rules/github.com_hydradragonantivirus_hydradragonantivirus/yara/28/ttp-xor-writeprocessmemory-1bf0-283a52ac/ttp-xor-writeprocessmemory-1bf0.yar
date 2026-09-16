rule TTP_XOR_WriteProcessMemory_1bf0 {
  strings:
    $key_1bf0 = { 4c 82 [2] 7e a0 [2] 78 95 [2] 56 95 [2] 69 89 }

  condition:
    any of them
}