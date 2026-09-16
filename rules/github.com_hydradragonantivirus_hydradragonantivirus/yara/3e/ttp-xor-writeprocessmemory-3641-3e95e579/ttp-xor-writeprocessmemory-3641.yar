rule TTP_XOR_WriteProcessMemory_3641 {
  strings:
    $key_3641 = { 61 33 [2] 53 11 [2] 55 24 [2] 7b 24 [2] 44 38 }

  condition:
    any of them
}