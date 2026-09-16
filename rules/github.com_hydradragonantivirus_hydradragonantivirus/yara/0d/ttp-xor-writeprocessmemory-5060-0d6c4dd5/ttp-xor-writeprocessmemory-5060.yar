rule TTP_XOR_WriteProcessMemory_5060 {
  strings:
    $key_5060 = { 07 12 [2] 35 30 [2] 33 05 [2] 1d 05 [2] 22 19 }

  condition:
    any of them
}