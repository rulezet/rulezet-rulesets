rule TTP_XOR_WriteProcessMemory_6905 {
  strings:
    $key_6905 = { 3e 77 [2] 0c 55 [2] 0a 60 [2] 24 60 [2] 1b 7c }

  condition:
    any of them
}