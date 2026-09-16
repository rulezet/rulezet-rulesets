rule TTP_XOR_WriteProcessMemory_5033 {
  strings:
    $key_5033 = { 07 41 [2] 35 63 [2] 33 56 [2] 1d 56 [2] 22 4a }

  condition:
    any of them
}