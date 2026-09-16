rule TTP_XOR_WriteProcessMemory_5013 {
  strings:
    $key_5013 = { 07 61 [2] 35 43 [2] 33 76 [2] 1d 76 [2] 22 6a }

  condition:
    any of them
}