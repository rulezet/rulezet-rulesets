rule TTP_XOR_WriteProcessMemory_6413 {
  strings:
    $key_6413 = { 33 61 [2] 01 43 [2] 07 76 [2] 29 76 [2] 16 6a }

  condition:
    any of them
}