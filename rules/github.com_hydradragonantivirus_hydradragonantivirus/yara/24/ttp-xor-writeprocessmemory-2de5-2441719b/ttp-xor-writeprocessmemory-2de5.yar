rule TTP_XOR_WriteProcessMemory_2de5 {
  strings:
    $key_2de5 = { 7a 97 [2] 48 b5 [2] 4e 80 [2] 60 80 [2] 5f 9c }

  condition:
    any of them
}