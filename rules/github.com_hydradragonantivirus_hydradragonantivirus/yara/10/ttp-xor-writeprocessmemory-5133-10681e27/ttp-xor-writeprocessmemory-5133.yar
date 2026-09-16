rule TTP_XOR_WriteProcessMemory_5133 {
  strings:
    $key_5133 = { 06 41 [2] 34 63 [2] 32 56 [2] 1c 56 [2] 23 4a }

  condition:
    any of them
}