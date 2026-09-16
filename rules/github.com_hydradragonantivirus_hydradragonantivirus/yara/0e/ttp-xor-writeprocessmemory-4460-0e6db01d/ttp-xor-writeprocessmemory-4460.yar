rule TTP_XOR_WriteProcessMemory_4460 {
  strings:
    $key_4460 = { 13 12 [2] 21 30 [2] 27 05 [2] 09 05 [2] 36 19 }

  condition:
    any of them
}