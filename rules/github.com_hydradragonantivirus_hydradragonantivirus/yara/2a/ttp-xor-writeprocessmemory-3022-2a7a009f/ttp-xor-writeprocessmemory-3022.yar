rule TTP_XOR_WriteProcessMemory_3022 {
  strings:
    $key_3022 = { 67 50 [2] 55 72 [2] 53 47 [2] 7d 47 [2] 42 5b }

  condition:
    any of them
}