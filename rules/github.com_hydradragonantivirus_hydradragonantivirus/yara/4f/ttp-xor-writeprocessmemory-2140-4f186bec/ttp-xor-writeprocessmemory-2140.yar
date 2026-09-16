rule TTP_XOR_WriteProcessMemory_2140 {
  strings:
    $key_2140 = { 76 32 [2] 44 10 [2] 42 25 [2] 6c 25 [2] 53 39 }

  condition:
    any of them
}