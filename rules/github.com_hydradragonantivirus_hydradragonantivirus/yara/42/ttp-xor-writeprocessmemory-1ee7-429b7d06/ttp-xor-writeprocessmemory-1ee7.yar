rule TTP_XOR_WriteProcessMemory_1ee7 {
  strings:
    $key_1ee7 = { 49 95 [2] 7b b7 [2] 7d 82 [2] 53 82 [2] 6c 9e }

  condition:
    any of them
}