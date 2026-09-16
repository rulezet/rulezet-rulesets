rule TTP_XOR_WriteProcessMemory_66e0 {
  strings:
    $key_66e0 = { 31 92 [2] 03 b0 [2] 05 85 [2] 2b 85 [2] 14 99 }

  condition:
    any of them
}