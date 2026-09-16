rule TTP_XOR_WriteProcessMemory_2805 {
  strings:
    $key_2805 = { 7f 77 [2] 4d 55 [2] 4b 60 [2] 65 60 [2] 5a 7c }

  condition:
    any of them
}