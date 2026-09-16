rule TTP_XOR_WriteProcessMemory_4422 {
  strings:
    $key_4422 = { 13 50 [2] 21 72 [2] 27 47 [2] 09 47 [2] 36 5b }

  condition:
    any of them
}