rule TTP_XOR_WriteProcessMemory_3f17 {
  strings:
    $key_3f17 = { 68 65 [2] 5a 47 [2] 5c 72 [2] 72 72 [2] 4d 6e }

  condition:
    any of them
}