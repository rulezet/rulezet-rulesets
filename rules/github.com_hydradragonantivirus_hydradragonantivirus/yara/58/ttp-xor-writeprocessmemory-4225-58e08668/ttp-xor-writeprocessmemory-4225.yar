rule TTP_XOR_WriteProcessMemory_4225 {
  strings:
    $key_4225 = { 15 57 [2] 27 75 [2] 21 40 [2] 0f 40 [2] 30 5c }

  condition:
    any of them
}