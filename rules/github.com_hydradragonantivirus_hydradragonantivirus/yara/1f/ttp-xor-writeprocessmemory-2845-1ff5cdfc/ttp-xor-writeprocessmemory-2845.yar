rule TTP_XOR_WriteProcessMemory_2845 {
  strings:
    $key_2845 = { 7f 37 [2] 4d 15 [2] 4b 20 [2] 65 20 [2] 5a 3c }

  condition:
    any of them
}