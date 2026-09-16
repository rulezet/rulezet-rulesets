rule TTP_XOR_WriteProcessMemory_4a06 {
  strings:
    $key_4a06 = { 1d 74 [2] 2f 56 [2] 29 63 [2] 07 63 [2] 38 7f }

  condition:
    any of them
}