rule TTP_XOR_WriteProcessMemory_6225 {
  strings:
    $key_6225 = { 35 57 [2] 07 75 [2] 01 40 [2] 2f 40 [2] 10 5c }

  condition:
    any of them
}