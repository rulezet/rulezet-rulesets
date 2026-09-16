rule TTP_XOR_WriteProcessMemory_0263 {
  strings:
    $key_0263 = { 55 11 [2] 67 33 [2] 61 06 [2] 4f 06 [2] 70 1a }

  condition:
    any of them
}