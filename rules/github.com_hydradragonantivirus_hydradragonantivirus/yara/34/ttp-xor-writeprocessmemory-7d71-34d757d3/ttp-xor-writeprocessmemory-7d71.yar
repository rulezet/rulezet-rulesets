rule TTP_XOR_WriteProcessMemory_7d71 {
  strings:
    $key_7d71 = { 2a 03 [2] 18 21 [2] 1e 14 [2] 30 14 [2] 0f 08 }

  condition:
    any of them
}