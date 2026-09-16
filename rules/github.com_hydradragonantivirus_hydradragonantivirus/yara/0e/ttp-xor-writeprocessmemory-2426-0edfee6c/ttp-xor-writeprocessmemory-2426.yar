rule TTP_XOR_WriteProcessMemory_2426 {
  strings:
    $key_2426 = { 73 54 [2] 41 76 [2] 47 43 [2] 69 43 [2] 56 5f }

  condition:
    any of them
}