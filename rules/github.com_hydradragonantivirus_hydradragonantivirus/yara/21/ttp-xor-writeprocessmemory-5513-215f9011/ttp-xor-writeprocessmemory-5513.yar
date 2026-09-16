rule TTP_XOR_WriteProcessMemory_5513 {
  strings:
    $key_5513 = { 02 61 [2] 30 43 [2] 36 76 [2] 18 76 [2] 27 6a }

  condition:
    any of them
}