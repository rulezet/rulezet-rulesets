rule TTP_XOR_WriteProcessMemory_3660 {
  strings:
    $key_3660 = { 61 12 [2] 53 30 [2] 55 05 [2] 7b 05 [2] 44 19 }

  condition:
    any of them
}