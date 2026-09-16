rule TTP_XOR_WriteProcessMemory_2422 {
  strings:
    $key_2422 = { 73 50 [2] 41 72 [2] 47 47 [2] 69 47 [2] 56 5b }

  condition:
    any of them
}