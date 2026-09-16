rule TTP_XOR_WriteProcessMemory_4313 {
  strings:
    $key_4313 = { 14 61 [2] 26 43 [2] 20 76 [2] 0e 76 [2] 31 6a }

  condition:
    any of them
}