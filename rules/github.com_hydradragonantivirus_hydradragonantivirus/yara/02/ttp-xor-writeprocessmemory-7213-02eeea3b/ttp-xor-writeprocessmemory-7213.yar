rule TTP_XOR_WriteProcessMemory_7213 {
  strings:
    $key_7213 = { 25 61 [2] 17 43 [2] 11 76 [2] 3f 76 [2] 00 6a }

  condition:
    any of them
}