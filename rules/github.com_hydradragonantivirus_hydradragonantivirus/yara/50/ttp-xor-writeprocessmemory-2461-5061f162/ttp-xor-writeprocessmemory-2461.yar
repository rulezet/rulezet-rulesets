rule TTP_XOR_WriteProcessMemory_2461 {
  strings:
    $key_2461 = { 73 13 [2] 41 31 [2] 47 04 [2] 69 04 [2] 56 18 }

  condition:
    any of them
}