rule TTP_XOR_WriteProcessMemory_1ff2 {
  strings:
    $key_1ff2 = { 48 80 [2] 7a a2 [2] 7c 97 [2] 52 97 [2] 6d 8b }

  condition:
    any of them
}