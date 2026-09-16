rule TTP_XOR_WriteProcessMemory_4b75 {
  strings:
    $key_4b75 = { 1c 07 [2] 2e 25 [2] 28 10 [2] 06 10 [2] 39 0c }

  condition:
    any of them
}