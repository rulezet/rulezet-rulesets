rule TTP_XOR_WriteProcessMemory_2136 {
  strings:
    $key_2136 = { 76 44 [2] 44 66 [2] 42 53 [2] 6c 53 [2] 53 4f }

  condition:
    any of them
}