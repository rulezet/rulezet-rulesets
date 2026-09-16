rule TTP_XOR_WriteProcessMemory_f512 {
  strings:
    $key_f512 = { a2 60 [2] 90 42 [2] 96 77 [2] b8 77 [2] 87 6b }

  condition:
    any of them
}