rule TTP_XOR_WriteProcessMemory_3af3 {
  strings:
    $key_3af3 = { 6d 81 [2] 5f a3 [2] 59 96 [2] 77 96 [2] 48 8a }

  condition:
    any of them
}