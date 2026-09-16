rule TTP_XOR_WriteProcessMemory_2445 {
  strings:
    $key_2445 = { 73 37 [2] 41 15 [2] 47 20 [2] 69 20 [2] 56 3c }

  condition:
    any of them
}