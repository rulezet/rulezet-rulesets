rule TTP_XOR_WriteProcessMemory_7871 {
  strings:
    $key_7871 = { 2f 03 [2] 1d 21 [2] 1b 14 [2] 35 14 [2] 0a 08 }

  condition:
    any of them
}