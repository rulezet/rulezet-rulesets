rule TTP_XOR_WriteProcessMemory_6232 {
  strings:
    $key_6232 = { 35 40 [2] 07 62 [2] 01 57 [2] 2f 57 [2] 10 4b }

  condition:
    any of them
}