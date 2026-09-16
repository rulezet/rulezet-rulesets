rule TTP_XOR_WriteProcessMemory_2453 {
  strings:
    $key_2453 = { 73 21 [2] 41 03 [2] 47 36 [2] 69 36 [2] 56 2a }

  condition:
    any of them
}