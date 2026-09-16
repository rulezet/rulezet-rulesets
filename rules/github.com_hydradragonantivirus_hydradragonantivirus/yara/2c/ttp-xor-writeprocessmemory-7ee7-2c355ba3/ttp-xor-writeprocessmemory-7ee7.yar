rule TTP_XOR_WriteProcessMemory_7ee7 {
  strings:
    $key_7ee7 = { 29 95 [2] 1b b7 [2] 1d 82 [2] 33 82 [2] 0c 9e }

  condition:
    any of them
}