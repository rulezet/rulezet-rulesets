rule TTP_XOR_WriteProcessMemory_6251 {
  strings:
    $key_6251 = { 35 23 [2] 07 01 [2] 01 34 [2] 2f 34 [2] 10 28 }

  condition:
    any of them
}