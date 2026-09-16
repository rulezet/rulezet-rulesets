rule TTP_XOR_WriteProcessMemory_19f2 {
  strings:
    $key_19f2 = { 4e 80 [2] 7c a2 [2] 7a 97 [2] 54 97 [2] 6b 8b }

  condition:
    any of them
}