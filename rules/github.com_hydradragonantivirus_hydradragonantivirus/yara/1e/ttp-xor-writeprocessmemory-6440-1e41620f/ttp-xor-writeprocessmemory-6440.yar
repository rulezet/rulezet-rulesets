rule TTP_XOR_WriteProcessMemory_6440 {
  strings:
    $key_6440 = { 33 32 [2] 01 10 [2] 07 25 [2] 29 25 [2] 16 39 }

  condition:
    any of them
}