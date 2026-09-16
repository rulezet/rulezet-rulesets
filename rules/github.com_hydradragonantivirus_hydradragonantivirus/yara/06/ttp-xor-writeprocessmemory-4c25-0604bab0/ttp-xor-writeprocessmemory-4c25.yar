rule TTP_XOR_WriteProcessMemory_4c25 {
  strings:
    $key_4c25 = { 1b 57 [2] 29 75 [2] 2f 40 [2] 01 40 [2] 3e 5c }

  condition:
    any of them
}