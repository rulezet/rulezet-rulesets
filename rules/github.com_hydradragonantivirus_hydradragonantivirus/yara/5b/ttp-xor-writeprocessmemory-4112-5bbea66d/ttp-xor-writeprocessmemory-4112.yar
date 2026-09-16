rule TTP_XOR_WriteProcessMemory_4112 {
  strings:
    $key_4112 = { 16 60 [2] 24 42 [2] 22 77 [2] 0c 77 [2] 33 6b }

  condition:
    any of them
}