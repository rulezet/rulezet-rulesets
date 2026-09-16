rule TTP_XOR_WriteProcessMemory_1f06 {
  strings:
    $key_1f06 = { 48 74 [2] 7a 56 [2] 7c 63 [2] 52 63 [2] 6d 7f }

  condition:
    any of them
}