rule TTP_XOR_WriteProcessMemory_2441 {
  strings:
    $key_2441 = { 73 33 [2] 41 11 [2] 47 24 [2] 69 24 [2] 56 38 }

  condition:
    any of them
}