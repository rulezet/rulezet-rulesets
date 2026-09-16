rule TTP_XOR_WriteProcessMemory_2435 {
  strings:
    $key_2435 = { 73 47 [2] 41 65 [2] 47 50 [2] 69 50 [2] 56 4c }

  condition:
    any of them
}