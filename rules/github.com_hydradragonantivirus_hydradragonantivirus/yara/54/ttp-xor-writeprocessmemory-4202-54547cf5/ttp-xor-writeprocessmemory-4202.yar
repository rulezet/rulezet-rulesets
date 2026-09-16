rule TTP_XOR_WriteProcessMemory_4202 {
  strings:
    $key_4202 = { 15 70 [2] 27 52 [2] 21 67 [2] 0f 67 [2] 30 7b }

  condition:
    any of them
}