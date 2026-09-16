rule TTP_XOR_WriteProcessMemory_7477 {
  strings:
    $key_7477 = { 23 05 [2] 11 27 [2] 17 12 [2] 39 12 [2] 06 0e }

  condition:
    any of them
}