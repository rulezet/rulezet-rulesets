rule TTP_XOR_WriteProcessMemory_6712 {
  strings:
    $key_6712 = { 30 60 [2] 02 42 [2] 04 77 [2] 2a 77 [2] 15 6b }

  condition:
    any of them
}