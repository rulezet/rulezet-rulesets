rule TTP_XOR_WriteProcessMemory_9405 {
  strings:
    $key_9405 = { c3 77 [2] f1 55 [2] f7 60 [2] d9 60 [2] e6 7c }

  condition:
    any of them
}