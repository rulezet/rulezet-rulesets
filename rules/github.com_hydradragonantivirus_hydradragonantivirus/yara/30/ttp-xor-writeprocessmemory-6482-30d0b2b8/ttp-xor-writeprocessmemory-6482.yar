rule TTP_XOR_WriteProcessMemory_6482 {
  strings:
    $key_6482 = { 33 f0 [2] 01 d2 [2] 07 e7 [2] 29 e7 [2] 16 fb }

  condition:
    any of them
}