rule TTP_XOR_WriteProcessMemory_6247 {
  strings:
    $key_6247 = { 35 35 [2] 07 17 [2] 01 22 [2] 2f 22 [2] 10 3e }

  condition:
    any of them
}