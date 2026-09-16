rule TTP_XOR_WriteProcessMemory_68d8 {
  strings:
    $key_68d8 = { 3f aa [2] 0d 88 [2] 0b bd [2] 25 bd [2] 1a a1 }

  condition:
    any of them
}