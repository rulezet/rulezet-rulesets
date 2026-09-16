rule TTP_XOR_WriteProcessMemory_3532 {
  strings:
    $key_3532 = { 62 40 [2] 50 62 [2] 56 57 [2] 78 57 [2] 47 4b }

  condition:
    any of them
}