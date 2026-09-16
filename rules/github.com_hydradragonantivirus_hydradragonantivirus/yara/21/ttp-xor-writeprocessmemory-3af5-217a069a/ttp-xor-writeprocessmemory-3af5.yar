rule TTP_XOR_WriteProcessMemory_3af5 {
  strings:
    $key_3af5 = { 6d 87 [2] 5f a5 [2] 59 90 [2] 77 90 [2] 48 8c }

  condition:
    any of them
}