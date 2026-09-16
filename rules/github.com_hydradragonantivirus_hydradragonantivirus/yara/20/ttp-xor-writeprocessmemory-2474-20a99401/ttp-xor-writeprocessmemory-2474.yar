rule TTP_XOR_WriteProcessMemory_2474 {
  strings:
    $key_2474 = { 73 06 [2] 41 24 [2] 47 11 [2] 69 11 [2] 56 0d }

  condition:
    any of them
}