rule TTP_XOR_WriteProcessMemory_0e33 {
  strings:
    $key_0e33 = { 59 41 [2] 6b 63 [2] 6d 56 [2] 43 56 [2] 7c 4a }

  condition:
    any of them
}