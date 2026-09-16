rule TTP_XOR_WriteProcessMemory_1ef2 {
  strings:
    $key_1ef2 = { 49 80 [2] 7b a2 [2] 7d 97 [2] 53 97 [2] 6c 8b }

  condition:
    any of them
}