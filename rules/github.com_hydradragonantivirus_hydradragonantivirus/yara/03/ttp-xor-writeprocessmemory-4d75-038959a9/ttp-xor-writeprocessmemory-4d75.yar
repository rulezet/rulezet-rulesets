rule TTP_XOR_WriteProcessMemory_4d75 {
  strings:
    $key_4d75 = { 1a 07 [2] 28 25 [2] 2e 10 [2] 00 10 [2] 3f 0c }

  condition:
    any of them
}