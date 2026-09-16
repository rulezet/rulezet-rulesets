rule TTP_XOR_WriteProcessMemory_6213 {
  strings:
    $key_6213 = { 35 61 [2] 07 43 [2] 01 76 [2] 2f 76 [2] 10 6a }

  condition:
    any of them
}