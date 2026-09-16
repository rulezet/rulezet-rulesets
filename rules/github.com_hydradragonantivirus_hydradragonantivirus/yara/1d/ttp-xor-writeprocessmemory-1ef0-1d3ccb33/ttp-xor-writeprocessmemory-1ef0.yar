rule TTP_XOR_WriteProcessMemory_1ef0 {
  strings:
    $key_1ef0 = { 49 82 [2] 7b a0 [2] 7d 95 [2] 53 95 [2] 6c 89 }

  condition:
    any of them
}