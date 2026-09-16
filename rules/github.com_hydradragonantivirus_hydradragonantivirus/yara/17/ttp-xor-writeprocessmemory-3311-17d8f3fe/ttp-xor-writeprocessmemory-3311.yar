rule TTP_XOR_WriteProcessMemory_3311 {
  strings:
    $key_3311 = { 64 63 [2] 56 41 [2] 50 74 [2] 7e 74 [2] 41 68 }

  condition:
    any of them
}