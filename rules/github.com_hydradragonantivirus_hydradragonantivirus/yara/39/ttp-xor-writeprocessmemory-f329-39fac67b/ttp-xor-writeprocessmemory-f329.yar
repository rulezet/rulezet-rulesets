rule TTP_XOR_WriteProcessMemory_f329 {
  strings:
    $key_f329 = { a4 5b [2] 96 79 [2] 90 4c [2] be 4c [2] 81 50 }

  condition:
    any of them
}