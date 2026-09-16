rule TTP_XOR_WriteProcessMemory_7413 {
  strings:
    $key_7413 = { 23 61 [2] 11 43 [2] 17 76 [2] 39 76 [2] 06 6a }

  condition:
    any of them
}