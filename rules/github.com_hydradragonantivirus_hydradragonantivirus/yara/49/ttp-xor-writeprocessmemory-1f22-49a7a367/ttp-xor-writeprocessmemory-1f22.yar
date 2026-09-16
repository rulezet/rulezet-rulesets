rule TTP_XOR_WriteProcessMemory_1f22 {
  strings:
    $key_1f22 = { 48 50 [2] 7a 72 [2] 7c 47 [2] 52 47 [2] 6d 5b }

  condition:
    any of them
}