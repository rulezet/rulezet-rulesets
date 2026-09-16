rule TTP_XOR_WriteProcessMemory_2520 {
  strings:
    $key_2520 = { 72 52 [2] 40 70 [2] 46 45 [2] 68 45 [2] 57 59 }

  condition:
    any of them
}