rule TTP_XOR_WriteProcessMemory_6253 {
  strings:
    $key_6253 = { 35 21 [2] 07 03 [2] 01 36 [2] 2f 36 [2] 10 2a }

  condition:
    any of them
}