rule TTP_XOR_WriteProcessMemory_5236 {
  strings:
    $key_5236 = { 05 44 [2] 37 66 [2] 31 53 [2] 1f 53 [2] 20 4f }

  condition:
    any of them
}