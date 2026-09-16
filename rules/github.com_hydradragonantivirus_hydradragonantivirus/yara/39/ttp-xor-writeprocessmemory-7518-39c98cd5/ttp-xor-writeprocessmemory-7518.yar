rule TTP_XOR_WriteProcessMemory_7518 {
  strings:
    $key_7518 = { 22 6a [2] 10 48 [2] 16 7d [2] 38 7d [2] 07 61 }

  condition:
    any of them
}