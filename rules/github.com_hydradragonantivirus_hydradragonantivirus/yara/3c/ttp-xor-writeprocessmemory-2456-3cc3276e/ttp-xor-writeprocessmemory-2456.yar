rule TTP_XOR_WriteProcessMemory_2456 {
  strings:
    $key_2456 = { 73 24 [2] 41 06 [2] 47 33 [2] 69 33 [2] 56 2f }

  condition:
    any of them
}