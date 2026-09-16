rule TTP_XOR_WriteProcessMemory_6da6 {
  strings:
    $key_6da6 = { 3a d4 [2] 08 f6 [2] 0e c3 [2] 20 c3 [2] 1f df }

  condition:
    any of them
}