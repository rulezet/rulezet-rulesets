rule TTP_XOR_WriteProcessMemory_2a12 {
  strings:
    $key_2a12 = { 7d 60 [2] 4f 42 [2] 49 77 [2] 67 77 [2] 58 6b }

  condition:
    any of them
}