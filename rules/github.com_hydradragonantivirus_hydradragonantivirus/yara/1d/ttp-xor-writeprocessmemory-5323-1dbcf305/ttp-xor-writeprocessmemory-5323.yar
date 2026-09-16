rule TTP_XOR_WriteProcessMemory_5323 {
  strings:
    $key_5323 = { 04 51 [2] 36 73 [2] 30 46 [2] 1e 46 [2] 21 5a }

  condition:
    any of them
}