rule TTP_XOR_WriteProcessMemory_3da6 {
  strings:
    $key_3da6 = { 6a d4 [2] 58 f6 [2] 5e c3 [2] 70 c3 [2] 4f df }

  condition:
    any of them
}