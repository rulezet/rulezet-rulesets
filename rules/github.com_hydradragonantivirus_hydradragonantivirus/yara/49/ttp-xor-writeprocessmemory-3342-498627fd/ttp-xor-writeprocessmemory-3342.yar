rule TTP_XOR_WriteProcessMemory_3342 {
  strings:
    $key_3342 = { 64 30 [2] 56 12 [2] 50 27 [2] 7e 27 [2] 41 3b }

  condition:
    any of them
}