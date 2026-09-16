rule TTP_XOR_WriteProcessMemory_6215 {
  strings:
    $key_6215 = { 35 67 [2] 07 45 [2] 01 70 [2] 2f 70 [2] 10 6c }

  condition:
    any of them
}