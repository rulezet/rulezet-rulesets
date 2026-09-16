rule TTP_XOR_WriteProcessMemory_6025 {
  strings:
    $key_6025 = { 37 57 [2] 05 75 [2] 03 40 [2] 2d 40 [2] 12 5c }

  condition:
    any of them
}