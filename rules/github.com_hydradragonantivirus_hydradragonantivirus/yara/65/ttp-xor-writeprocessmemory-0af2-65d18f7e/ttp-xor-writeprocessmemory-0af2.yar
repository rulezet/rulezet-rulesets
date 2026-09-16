rule TTP_XOR_WriteProcessMemory_0af2 {
  strings:
    $key_0af2 = { 5d 80 [2] 6f a2 [2] 69 97 [2] 47 97 [2] 78 8b }

  condition:
    any of them
}