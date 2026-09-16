rule TTP_XOR_WriteProcessMemory_0ef2 {
  strings:
    $key_0ef2 = { 59 80 [2] 6b a2 [2] 6d 97 [2] 43 97 [2] 7c 8b }

  condition:
    any of them
}