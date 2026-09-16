rule TTP_XOR_WriteProcessMemory_7835 {
  strings:
    $key_7835 = { 2f 47 [2] 1d 65 [2] 1b 50 [2] 35 50 [2] 0a 4c }

  condition:
    any of them
}