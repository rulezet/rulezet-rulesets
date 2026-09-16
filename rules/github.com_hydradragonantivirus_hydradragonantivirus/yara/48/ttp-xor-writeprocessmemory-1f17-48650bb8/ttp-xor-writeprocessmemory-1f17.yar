rule TTP_XOR_WriteProcessMemory_1f17 {
  strings:
    $key_1f17 = { 48 65 [2] 7a 47 [2] 7c 72 [2] 52 72 [2] 6d 6e }

  condition:
    any of them
}