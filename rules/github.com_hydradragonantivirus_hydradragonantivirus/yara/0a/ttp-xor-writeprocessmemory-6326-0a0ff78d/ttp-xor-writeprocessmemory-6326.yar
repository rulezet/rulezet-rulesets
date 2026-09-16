rule TTP_XOR_WriteProcessMemory_6326 {
  strings:
    $key_6326 = { 34 54 [2] 06 76 [2] 00 43 [2] 2e 43 [2] 11 5f }

  condition:
    any of them
}