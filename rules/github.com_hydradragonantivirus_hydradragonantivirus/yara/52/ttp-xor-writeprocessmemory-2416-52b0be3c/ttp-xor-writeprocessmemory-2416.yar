rule TTP_XOR_WriteProcessMemory_2416 {
  strings:
    $key_2416 = { 73 64 [2] 41 46 [2] 47 73 [2] 69 73 [2] 56 6f }

  condition:
    any of them
}