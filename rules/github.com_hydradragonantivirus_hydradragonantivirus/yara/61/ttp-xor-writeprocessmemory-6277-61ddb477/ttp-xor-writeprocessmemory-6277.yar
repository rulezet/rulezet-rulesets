rule TTP_XOR_WriteProcessMemory_6277 {
  strings:
    $key_6277 = { 35 05 [2] 07 27 [2] 01 12 [2] 2f 12 [2] 10 0e }

  condition:
    any of them
}