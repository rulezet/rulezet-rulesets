rule TTP_XOR_WriteProcessMemory_0212 {
  strings:
    $key_0212 = { 55 60 [2] 67 42 [2] 61 77 [2] 4f 77 [2] 70 6b }

  condition:
    any of them
}