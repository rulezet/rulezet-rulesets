rule TTP_XOR_WriteProcessMemory_6626 {
  strings:
    $key_6626 = { 31 54 [2] 03 76 [2] 05 43 [2] 2b 43 [2] 14 5f }

  condition:
    any of them
}