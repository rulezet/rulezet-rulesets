rule TTP_XOR_WriteProcessMemory_6e05 {
  strings:
    $key_6e05 = { 39 77 [2] 0b 55 [2] 0d 60 [2] 23 60 [2] 1c 7c }

  condition:
    any of them
}