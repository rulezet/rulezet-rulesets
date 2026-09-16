rule TTP_XOR_WriteProcessMemory_2905 {
  strings:
    $key_2905 = { 7e 77 [2] 4c 55 [2] 4a 60 [2] 64 60 [2] 5b 7c }

  condition:
    any of them
}