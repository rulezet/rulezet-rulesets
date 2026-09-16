rule TTP_XOR_WriteProcessMemory_6222 {
  strings:
    $key_6222 = { 35 50 [2] 07 72 [2] 01 47 [2] 2f 47 [2] 10 5b }

  condition:
    any of them
}