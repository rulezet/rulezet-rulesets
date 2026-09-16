rule TTP_XOR_WriteProcessMemory_2475 {
  strings:
    $key_2475 = { 73 07 [2] 41 25 [2] 47 10 [2] 69 10 [2] 56 0c }

  condition:
    any of them
}