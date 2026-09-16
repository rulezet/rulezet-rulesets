rule TTP_XOR_WriteProcessMemory_eec2 {
  strings:
    $key_eec2 = { b9 b0 [2] 8b 92 [2] 8d a7 [2] a3 a7 [2] 9c bb }

  condition:
    any of them
}