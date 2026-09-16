rule TTP_XOR_WriteProcessMemory_f505 {
  strings:
    $key_f505 = { a2 77 [2] 90 55 [2] 96 60 [2] b8 60 [2] 87 7c }

  condition:
    any of them
}