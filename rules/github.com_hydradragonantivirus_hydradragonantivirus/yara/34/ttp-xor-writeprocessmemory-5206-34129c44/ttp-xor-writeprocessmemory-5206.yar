rule TTP_XOR_WriteProcessMemory_5206 {
  strings:
    $key_5206 = { 05 74 [2] 37 56 [2] 31 63 [2] 1f 63 [2] 20 7f }

  condition:
    any of them
}