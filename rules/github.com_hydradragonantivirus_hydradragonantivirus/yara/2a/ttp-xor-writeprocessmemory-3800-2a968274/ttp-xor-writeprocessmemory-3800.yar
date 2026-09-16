rule TTP_XOR_WriteProcessMemory_3800 {
  strings:
    $key_3800 = { 6f 72 [2] 5d 50 [2] 5b 65 [2] 75 65 [2] 4a 79 }

  condition:
    any of them
}