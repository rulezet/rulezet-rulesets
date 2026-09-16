rule TTP_XOR_WriteProcessMemory_3406 {
  strings:
    $key_3406 = { 63 74 [2] 51 56 [2] 57 63 [2] 79 63 [2] 46 7f }

  condition:
    any of them
}