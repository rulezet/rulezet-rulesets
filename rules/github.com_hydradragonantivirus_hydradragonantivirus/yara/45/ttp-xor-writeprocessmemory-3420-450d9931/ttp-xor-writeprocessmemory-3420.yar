rule TTP_XOR_WriteProcessMemory_3420 {
  strings:
    $key_3420 = { 63 52 [2] 51 70 [2] 57 45 [2] 79 45 [2] 46 59 }

  condition:
    any of them
}