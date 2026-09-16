rule TTP_XOR_WriteProcessMemory_2405 {
  strings:
    $key_2405 = { 73 77 [2] 41 55 [2] 47 60 [2] 69 60 [2] 56 7c }

  condition:
    any of them
}