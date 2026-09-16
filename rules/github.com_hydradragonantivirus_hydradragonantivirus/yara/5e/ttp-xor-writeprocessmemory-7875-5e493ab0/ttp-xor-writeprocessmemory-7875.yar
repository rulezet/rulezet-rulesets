rule TTP_XOR_WriteProcessMemory_7875 {
  strings:
    $key_7875 = { 2f 07 [2] 1d 25 [2] 1b 10 [2] 35 10 [2] 0a 0c }

  condition:
    any of them
}