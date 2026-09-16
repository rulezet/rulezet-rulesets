rule TTP_XOR_WriteProcessMemory_3006 {
  strings:
    $key_3006 = { 67 74 [2] 55 56 [2] 53 63 [2] 7d 63 [2] 42 7f }

  condition:
    any of them
}