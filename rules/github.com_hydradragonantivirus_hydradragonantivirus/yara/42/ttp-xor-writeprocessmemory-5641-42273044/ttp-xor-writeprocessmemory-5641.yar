rule TTP_XOR_WriteProcessMemory_5641 {
  strings:
    $key_5641 = { 01 33 [2] 33 11 [2] 35 24 [2] 1b 24 [2] 24 38 }

  condition:
    any of them
}