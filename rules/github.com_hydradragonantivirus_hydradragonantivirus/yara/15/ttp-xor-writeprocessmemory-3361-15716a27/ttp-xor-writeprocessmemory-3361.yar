rule TTP_XOR_WriteProcessMemory_3361 {
  strings:
    $key_3361 = { 64 13 [2] 56 31 [2] 50 04 [2] 7e 04 [2] 41 18 }

  condition:
    any of them
}