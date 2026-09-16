rule TTP_XOR_WriteProcessMemory_5175 {
  strings:
    $key_5175 = { 06 07 [2] 34 25 [2] 32 10 [2] 1c 10 [2] 23 0c }

  condition:
    any of them
}