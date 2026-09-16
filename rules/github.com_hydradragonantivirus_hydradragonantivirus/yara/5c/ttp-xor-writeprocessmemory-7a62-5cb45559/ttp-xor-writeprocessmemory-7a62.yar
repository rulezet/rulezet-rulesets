rule TTP_XOR_WriteProcessMemory_7a62 {
  strings:
    $key_7a62 = { 2d 10 [2] 1f 32 [2] 19 07 [2] 37 07 [2] 08 1b }

  condition:
    any of them
}