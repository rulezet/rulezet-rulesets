rule TTP_XOR_WriteProcessMemory_7451 {
  strings:
    $key_7451 = { 23 23 [2] 11 01 [2] 17 34 [2] 39 34 [2] 06 28 }

  condition:
    any of them
}