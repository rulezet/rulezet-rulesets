rule TTP_XOR_WriteProcessMemory_0d45 {
  strings:
    $key_0d45 = { 5a 37 [2] 68 15 [2] 6e 20 [2] 40 20 [2] 7f 3c }

  condition:
    any of them
}