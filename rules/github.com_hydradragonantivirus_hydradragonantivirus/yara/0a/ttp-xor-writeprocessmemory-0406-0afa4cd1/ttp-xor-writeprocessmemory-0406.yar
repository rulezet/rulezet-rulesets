rule TTP_XOR_WriteProcessMemory_0406 {
  strings:
    $key_0406 = { 53 74 [2] 61 56 [2] 67 63 [2] 49 63 [2] 76 7f }

  condition:
    any of them
}