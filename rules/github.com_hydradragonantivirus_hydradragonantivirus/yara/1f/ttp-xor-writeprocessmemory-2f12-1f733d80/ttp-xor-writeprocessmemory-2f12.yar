rule TTP_XOR_WriteProcessMemory_2f12 {
  strings:
    $key_2f12 = { 78 60 [2] 4a 42 [2] 4c 77 [2] 62 77 [2] 5d 6b }

  condition:
    any of them
}