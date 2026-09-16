rule TTP_XOR_WriteProcessMemory_3f12 {
  strings:
    $key_3f12 = { 68 60 [2] 5a 42 [2] 5c 77 [2] 72 77 [2] 4d 6b }

  condition:
    any of them
}