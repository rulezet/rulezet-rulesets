rule TTP_XOR_WriteProcessMemory_6ef0 {
  strings:
    $key_6ef0 = { 39 82 [2] 0b a0 [2] 0d 95 [2] 23 95 [2] 1c 89 }

  condition:
    any of them
}