rule TTP_XOR_WriteProcessMemory_6ee7 {
  strings:
    $key_6ee7 = { 39 95 [2] 0b b7 [2] 0d 82 [2] 23 82 [2] 1c 9e }

  condition:
    any of them
}