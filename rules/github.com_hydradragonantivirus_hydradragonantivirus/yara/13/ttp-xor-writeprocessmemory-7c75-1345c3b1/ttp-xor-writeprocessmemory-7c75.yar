rule TTP_XOR_WriteProcessMemory_7c75 {
  strings:
    $key_7c75 = { 2b 07 [2] 19 25 [2] 1f 10 [2] 31 10 [2] 0e 0c }

  condition:
    any of them
}