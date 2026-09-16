rule TTP_XOR_WriteProcessMemory_6d45 {
  strings:
    $key_6d45 = { 3a 37 [2] 08 15 [2] 0e 20 [2] 20 20 [2] 1f 3c }

  condition:
    any of them
}