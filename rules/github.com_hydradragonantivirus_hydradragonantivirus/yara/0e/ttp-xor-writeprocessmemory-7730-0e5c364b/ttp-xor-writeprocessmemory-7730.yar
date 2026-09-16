rule TTP_XOR_WriteProcessMemory_7730 {
  strings:
    $key_7730 = { 20 42 [2] 12 60 [2] 14 55 [2] 3a 55 [2] 05 49 }

  condition:
    any of them
}