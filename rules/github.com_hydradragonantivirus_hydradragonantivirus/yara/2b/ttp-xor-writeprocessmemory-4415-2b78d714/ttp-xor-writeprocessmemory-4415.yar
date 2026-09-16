rule TTP_XOR_WriteProcessMemory_4415 {
  strings:
    $key_4415 = { 13 67 [2] 21 45 [2] 27 70 [2] 09 70 [2] 36 6c }

  condition:
    any of them
}