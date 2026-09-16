rule TTP_XOR_WriteProcessMemory_6476 {
  strings:
    $key_6476 = { 33 04 [2] 01 26 [2] 07 13 [2] 29 13 [2] 16 0f }

  condition:
    any of them
}