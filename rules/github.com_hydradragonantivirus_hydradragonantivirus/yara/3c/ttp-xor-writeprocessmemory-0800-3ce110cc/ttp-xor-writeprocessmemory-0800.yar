rule TTP_XOR_WriteProcessMemory_0800 {
  strings:
    $key_0800 = { 5f 72 [2] 6d 50 [2] 6b 65 [2] 45 65 [2] 7a 79 }

  condition:
    any of them
}