rule TTP_XOR_WriteProcessMemory_6262 {
  strings:
    $key_6262 = { 35 10 [2] 07 32 [2] 01 07 [2] 2f 07 [2] 10 1b }

  condition:
    any of them
}