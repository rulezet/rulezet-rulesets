rule TTP_XOR_WriteProcessMemory_2ee7 {
  strings:
    $key_2ee7 = { 79 95 [2] 4b b7 [2] 4d 82 [2] 63 82 [2] 5c 9e }

  condition:
    any of them
}