rule TTP_XOR_WriteProcessMemory_2225 {
  strings:
    $key_2225 = { 75 57 [2] 47 75 [2] 41 40 [2] 6f 40 [2] 50 5c }

  condition:
    any of them
}