rule TTP_XOR_WriteProcessMemory_3206 {
  strings:
    $key_3206 = { 65 74 [2] 57 56 [2] 51 63 [2] 7f 63 [2] 40 7f }

  condition:
    any of them
}