rule TTP_XOR_WriteProcessMemory_20f2 {
  strings:
    $key_20f2 = { 77 80 [2] 45 a2 [2] 43 97 [2] 6d 97 [2] 52 8b }

  condition:
    any of them
}