rule TTP_XOR_WriteProcessMemory_3333 {
  strings:
    $key_3333 = { 64 41 [2] 56 63 [2] 50 56 [2] 7e 56 [2] 41 4a }

  condition:
    any of them
}