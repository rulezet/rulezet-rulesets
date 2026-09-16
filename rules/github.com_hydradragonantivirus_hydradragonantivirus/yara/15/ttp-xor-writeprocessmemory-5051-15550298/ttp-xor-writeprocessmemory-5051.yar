rule TTP_XOR_WriteProcessMemory_5051 {
  strings:
    $key_5051 = { 07 23 [2] 35 01 [2] 33 34 [2] 1d 34 [2] 22 28 }

  condition:
    any of them
}