rule TTP_XOR_WriteProcessMemory_3ff0 {
  strings:
    $key_3ff0 = { 68 82 [2] 5a a0 [2] 5c 95 [2] 72 95 [2] 4d 89 }

  condition:
    any of them
}