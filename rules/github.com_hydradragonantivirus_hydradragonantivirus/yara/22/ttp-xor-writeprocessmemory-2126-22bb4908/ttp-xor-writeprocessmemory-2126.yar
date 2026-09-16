rule TTP_XOR_WriteProcessMemory_2126 {
  strings:
    $key_2126 = { 76 54 [2] 44 76 [2] 42 43 [2] 6c 43 [2] 53 5f }

  condition:
    any of them
}