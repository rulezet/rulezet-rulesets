rule TTP_XOR_WriteProcessMemory_4233 {
  strings:
    $key_4233 = { 15 41 [2] 27 63 [2] 21 56 [2] 0f 56 [2] 30 4a }

  condition:
    any of them
}