rule TTP_XOR_WriteProcessMemory_7e05 {
  strings:
    $key_7e05 = { 29 77 [2] 1b 55 [2] 1d 60 [2] 33 60 [2] 0c 7c }

  condition:
    any of them
}