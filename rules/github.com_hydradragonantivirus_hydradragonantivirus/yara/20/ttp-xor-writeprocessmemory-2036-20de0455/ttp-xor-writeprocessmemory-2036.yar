rule TTP_XOR_WriteProcessMemory_2036 {
  strings:
    $key_2036 = { 77 44 [2] 45 66 [2] 43 53 [2] 6d 53 [2] 52 4f }

  condition:
    any of them
}