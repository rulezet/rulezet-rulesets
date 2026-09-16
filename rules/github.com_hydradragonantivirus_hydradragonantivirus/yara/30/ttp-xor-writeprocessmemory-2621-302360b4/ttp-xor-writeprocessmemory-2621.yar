rule TTP_XOR_WriteProcessMemory_2621 {
  strings:
    $key_2621 = { 71 53 [2] 43 71 [2] 45 44 [2] 6b 44 [2] 54 58 }

  condition:
    any of them
}