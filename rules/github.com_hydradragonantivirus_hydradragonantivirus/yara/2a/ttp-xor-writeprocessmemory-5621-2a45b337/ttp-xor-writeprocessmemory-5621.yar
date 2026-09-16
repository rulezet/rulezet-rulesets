rule TTP_XOR_WriteProcessMemory_5621 {
  strings:
    $key_5621 = { 01 53 [2] 33 71 [2] 35 44 [2] 1b 44 [2] 24 58 }

  condition:
    any of them
}