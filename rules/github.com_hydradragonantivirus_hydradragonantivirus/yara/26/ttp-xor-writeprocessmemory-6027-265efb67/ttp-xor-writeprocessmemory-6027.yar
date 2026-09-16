rule TTP_XOR_WriteProcessMemory_6027 {
  strings:
    $key_6027 = { 37 55 [2] 05 77 [2] 03 42 [2] 2d 42 [2] 12 5e }

  condition:
    any of them
}