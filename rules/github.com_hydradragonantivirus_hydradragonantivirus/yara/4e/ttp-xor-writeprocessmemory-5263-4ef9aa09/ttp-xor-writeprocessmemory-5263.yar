rule TTP_XOR_WriteProcessMemory_5263 {
  strings:
    $key_5263 = { 05 11 [2] 37 33 [2] 31 06 [2] 1f 06 [2] 20 1a }

  condition:
    any of them
}