rule TTP_XOR_WriteProcessMemory_8aeb {
  strings:
    $key_8aeb = { dd 99 [2] ef bb [2] e9 8e [2] c7 8e [2] f8 92 }

  condition:
    any of them
}