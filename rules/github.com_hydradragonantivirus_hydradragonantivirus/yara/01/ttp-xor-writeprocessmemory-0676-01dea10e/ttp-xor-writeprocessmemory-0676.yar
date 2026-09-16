rule TTP_XOR_WriteProcessMemory_0676 {
  strings:
    $key_0676 = { 51 04 [2] 63 26 [2] 65 13 [2] 4b 13 [2] 74 0f }

  condition:
    any of them
}