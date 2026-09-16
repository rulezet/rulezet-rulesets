rule TTP_XOR_WriteProcessMemory_4c45 {
  strings:
    $key_4c45 = { 1b 37 [2] 29 15 [2] 2f 20 [2] 01 20 [2] 3e 3c }

  condition:
    any of them
}