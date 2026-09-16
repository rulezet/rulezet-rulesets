rule TTP_XOR_WriteProcessMemory_3461 {
  strings:
    $key_3461 = { 63 13 [2] 51 31 [2] 57 04 [2] 79 04 [2] 46 18 }

  condition:
    any of them
}