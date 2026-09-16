rule TTP_XOR_WriteProcessMemory_6266 {
  strings:
    $key_6266 = { 35 14 [2] 07 36 [2] 01 03 [2] 2f 03 [2] 10 1f }

  condition:
    any of them
}