rule TTP_XOR_WriteProcessMemory_3276 {
  strings:
    $key_3276 = { 65 04 [2] 57 26 [2] 51 13 [2] 7f 13 [2] 40 0f }

  condition:
    any of them
}