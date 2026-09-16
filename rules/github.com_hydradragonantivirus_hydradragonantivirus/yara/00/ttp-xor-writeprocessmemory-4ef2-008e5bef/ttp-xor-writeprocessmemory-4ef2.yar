rule TTP_XOR_WriteProcessMemory_4ef2 {
  strings:
    $key_4ef2 = { 19 80 [2] 2b a2 [2] 2d 97 [2] 03 97 [2] 3c 8b }

  condition:
    any of them
}