rule TTP_XOR_WriteProcessMemory_ea77 {
  strings:
    $key_ea77 = { bd 05 [2] 8f 27 [2] 89 12 [2] a7 12 [2] 98 0e }

  condition:
    any of them
}