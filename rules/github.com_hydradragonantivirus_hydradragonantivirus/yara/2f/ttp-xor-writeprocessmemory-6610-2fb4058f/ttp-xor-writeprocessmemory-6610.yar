rule TTP_XOR_WriteProcessMemory_6610 {
  strings:
    $key_6610 = { 31 62 [2] 03 40 [2] 05 75 [2] 2b 75 [2] 14 69 }

  condition:
    any of them
}