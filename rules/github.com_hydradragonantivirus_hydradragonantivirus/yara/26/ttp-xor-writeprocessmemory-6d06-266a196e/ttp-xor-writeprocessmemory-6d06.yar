rule TTP_XOR_WriteProcessMemory_6d06 {
  strings:
    $key_6d06 = { 3a 74 [2] 08 56 [2] 0e 63 [2] 20 63 [2] 1f 7f }

  condition:
    any of them
}