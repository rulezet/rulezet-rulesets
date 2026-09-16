rule TTP_XOR_WriteProcessMemory_7f22 {
  strings:
    $key_7f22 = { 28 50 [2] 1a 72 [2] 1c 47 [2] 32 47 [2] 0d 5b }

  condition:
    any of them
}