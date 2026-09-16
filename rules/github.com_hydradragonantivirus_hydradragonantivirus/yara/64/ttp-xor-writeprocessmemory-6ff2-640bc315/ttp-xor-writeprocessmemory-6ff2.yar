rule TTP_XOR_WriteProcessMemory_6ff2 {
  strings:
    $key_6ff2 = { 38 80 [2] 0a a2 [2] 0c 97 [2] 22 97 [2] 1d 8b }

  condition:
    any of them
}