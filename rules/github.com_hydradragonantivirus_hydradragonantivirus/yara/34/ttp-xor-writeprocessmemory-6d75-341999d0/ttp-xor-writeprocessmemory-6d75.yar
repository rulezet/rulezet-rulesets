rule TTP_XOR_WriteProcessMemory_6d75 {
  strings:
    $key_6d75 = { 3a 07 [2] 08 25 [2] 0e 10 [2] 20 10 [2] 1f 0c }

  condition:
    any of them
}