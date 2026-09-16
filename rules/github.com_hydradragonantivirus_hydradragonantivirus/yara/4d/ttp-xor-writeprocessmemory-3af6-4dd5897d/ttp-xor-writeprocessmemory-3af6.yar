rule TTP_XOR_WriteProcessMemory_3af6 {
  strings:
    $key_3af6 = { 6d 84 [2] 5f a6 [2] 59 93 [2] 77 93 [2] 48 8f }

  condition:
    any of them
}