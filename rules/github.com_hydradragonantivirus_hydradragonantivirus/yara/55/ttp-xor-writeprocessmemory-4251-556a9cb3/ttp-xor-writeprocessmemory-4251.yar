rule TTP_XOR_WriteProcessMemory_4251 {
  strings:
    $key_4251 = { 15 23 [2] 27 01 [2] 21 34 [2] 0f 34 [2] 30 28 }

  condition:
    any of them
}