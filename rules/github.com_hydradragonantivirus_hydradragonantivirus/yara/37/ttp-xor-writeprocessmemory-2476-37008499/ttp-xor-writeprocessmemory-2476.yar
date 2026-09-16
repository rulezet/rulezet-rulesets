rule TTP_XOR_WriteProcessMemory_2476 {
  strings:
    $key_2476 = { 73 04 [2] 41 26 [2] 47 13 [2] 69 13 [2] 56 0f }

  condition:
    any of them
}