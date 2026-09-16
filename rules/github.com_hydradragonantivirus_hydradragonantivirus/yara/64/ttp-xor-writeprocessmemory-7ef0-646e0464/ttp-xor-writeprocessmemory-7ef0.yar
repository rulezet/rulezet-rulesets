rule TTP_XOR_WriteProcessMemory_7ef0 {
  strings:
    $key_7ef0 = { 29 82 [2] 1b a0 [2] 1d 95 [2] 33 95 [2] 0c 89 }

  condition:
    any of them
}