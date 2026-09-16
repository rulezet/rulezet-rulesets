rule TTP_XOR_WriteProcessMemory_1ff0 {
  strings:
    $key_1ff0 = { 48 82 [2] 7a a0 [2] 7c 95 [2] 52 95 [2] 6d 89 }

  condition:
    any of them
}