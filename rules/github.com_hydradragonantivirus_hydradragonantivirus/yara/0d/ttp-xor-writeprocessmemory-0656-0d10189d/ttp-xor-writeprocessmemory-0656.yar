rule TTP_XOR_WriteProcessMemory_0656 {
  strings:
    $key_0656 = { 51 24 [2] 63 06 [2] 65 33 [2] 4b 33 [2] 74 2f }

  condition:
    any of them
}