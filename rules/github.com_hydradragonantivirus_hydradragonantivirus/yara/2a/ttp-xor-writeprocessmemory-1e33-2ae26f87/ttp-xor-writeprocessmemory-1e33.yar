rule TTP_XOR_WriteProcessMemory_1e33 {
  strings:
    $key_1e33 = { 49 41 [2] 7b 63 [2] 7d 56 [2] 53 56 [2] 6c 4a }

  condition:
    any of them
}