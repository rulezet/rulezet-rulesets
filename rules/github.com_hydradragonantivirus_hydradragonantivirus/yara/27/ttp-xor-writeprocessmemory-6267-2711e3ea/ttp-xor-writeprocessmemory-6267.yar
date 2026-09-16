rule TTP_XOR_WriteProcessMemory_6267 {
  strings:
    $key_6267 = { 35 15 [2] 07 37 [2] 01 02 [2] 2f 02 [2] 10 1e }

  condition:
    any of them
}