rule TTP_XOR_WriteProcessMemory_6547 {
  strings:
    $key_6547 = { 32 35 [2] 00 17 [2] 06 22 [2] 28 22 [2] 17 3e }

  condition:
    any of them
}