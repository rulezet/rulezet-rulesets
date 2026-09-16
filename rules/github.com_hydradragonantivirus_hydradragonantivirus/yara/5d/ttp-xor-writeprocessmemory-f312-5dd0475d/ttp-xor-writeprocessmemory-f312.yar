rule TTP_XOR_WriteProcessMemory_f312 {
  strings:
    $key_f312 = { a4 60 [2] 96 42 [2] 90 77 [2] be 77 [2] 81 6b }

  condition:
    any of them
}