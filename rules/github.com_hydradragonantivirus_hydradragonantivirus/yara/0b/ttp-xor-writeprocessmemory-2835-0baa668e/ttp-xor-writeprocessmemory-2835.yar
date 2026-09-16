rule TTP_XOR_WriteProcessMemory_2835 {
  strings:
    $key_2835 = { 7f 47 [2] 4d 65 [2] 4b 50 [2] 65 50 [2] 5a 4c }

  condition:
    any of them
}