rule TTP_XOR_WriteProcessMemory_4a13 {
  strings:
    $key_4a13 = { 1d 61 [2] 2f 43 [2] 29 76 [2] 07 76 [2] 38 6a }

  condition:
    any of them
}