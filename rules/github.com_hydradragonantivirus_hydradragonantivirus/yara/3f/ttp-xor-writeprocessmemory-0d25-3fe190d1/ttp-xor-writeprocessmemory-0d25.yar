rule TTP_XOR_WriteProcessMemory_0d25 {
  strings:
    $key_0d25 = { 5a 57 [2] 68 75 [2] 6e 40 [2] 40 40 [2] 7f 5c }

  condition:
    any of them
}