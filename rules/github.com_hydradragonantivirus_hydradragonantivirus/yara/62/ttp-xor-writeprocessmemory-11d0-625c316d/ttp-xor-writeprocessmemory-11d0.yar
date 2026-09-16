rule TTP_XOR_WriteProcessMemory_11d0 {
  strings:
    $key_11d0 = { 46 a2 [2] 74 80 [2] 72 b5 [2] 5c b5 [2] 63 a9 }

  condition:
    any of them
}