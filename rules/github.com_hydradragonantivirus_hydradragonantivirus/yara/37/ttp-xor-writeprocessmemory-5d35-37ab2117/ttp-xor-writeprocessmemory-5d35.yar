rule TTP_XOR_WriteProcessMemory_5d35 {
  strings:
    $key_5d35 = { 0a 47 [2] 38 65 [2] 3e 50 [2] 10 50 [2] 2f 4c }

  condition:
    any of them
}