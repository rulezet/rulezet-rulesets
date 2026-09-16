rule TTP_XOR_WriteProcessMemory_7c45 {
  strings:
    $key_7c45 = { 2b 37 [2] 19 15 [2] 1f 20 [2] 31 20 [2] 0e 3c }

  condition:
    any of them
}