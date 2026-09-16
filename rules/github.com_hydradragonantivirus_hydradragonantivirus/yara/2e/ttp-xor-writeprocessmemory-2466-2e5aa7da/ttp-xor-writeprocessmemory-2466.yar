rule TTP_XOR_WriteProcessMemory_2466 {
  strings:
    $key_2466 = { 73 14 [2] 41 36 [2] 47 03 [2] 69 03 [2] 56 1f }

  condition:
    any of them
}