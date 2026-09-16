rule TTP_XOR_WriteProcessMemory_7306 {
  strings:
    $key_7306 = { 24 74 [2] 16 56 [2] 10 63 [2] 3e 63 [2] 01 7f }

  condition:
    any of them
}