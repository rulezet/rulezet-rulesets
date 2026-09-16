rule TTP_XOR_WriteProcessMemory_ccb9 {
  strings:
    $key_ccb9 = { 9b cb [2] a9 e9 [2] af dc [2] 81 dc [2] be c0 }

  condition:
    any of them
}