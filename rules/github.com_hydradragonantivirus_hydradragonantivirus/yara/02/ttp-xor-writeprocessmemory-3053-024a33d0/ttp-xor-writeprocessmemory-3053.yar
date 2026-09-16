rule TTP_XOR_WriteProcessMemory_3053 {
  strings:
    $key_3053 = { 67 21 [2] 55 03 [2] 53 36 [2] 7d 36 [2] 42 2a }

  condition:
    any of them
}