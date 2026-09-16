rule TTP_XOR_WriteProcessMemory_0ef0 {
  strings:
    $key_0ef0 = { 59 82 [2] 6b a0 [2] 6d 95 [2] 43 95 [2] 7c 89 }

  condition:
    any of them
}