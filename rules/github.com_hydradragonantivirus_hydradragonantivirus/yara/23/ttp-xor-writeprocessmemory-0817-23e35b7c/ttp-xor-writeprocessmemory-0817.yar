rule TTP_XOR_WriteProcessMemory_0817 {
  strings:
    $key_0817 = { 5f 65 [2] 6d 47 [2] 6b 72 [2] 45 72 [2] 7a 6e }

  condition:
    any of them
}