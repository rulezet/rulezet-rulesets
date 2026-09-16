rule TTP_XOR_WriteProcessMemory_2465 {
  strings:
    $key_2465 = { 73 17 [2] 41 35 [2] 47 00 [2] 69 00 [2] 56 1c }

  condition:
    any of them
}