rule TTP_XOR_WriteProcessMemory_7377 {
  strings:
    $key_7377 = { 24 05 [2] 16 27 [2] 10 12 [2] 3e 12 [2] 01 0e }

  condition:
    any of them
}