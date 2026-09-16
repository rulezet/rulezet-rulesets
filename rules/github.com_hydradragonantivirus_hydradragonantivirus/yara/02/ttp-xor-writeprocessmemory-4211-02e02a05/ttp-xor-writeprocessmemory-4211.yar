rule TTP_XOR_WriteProcessMemory_4211 {
  strings:
    $key_4211 = { 15 63 [2] 27 41 [2] 21 74 [2] 0f 74 [2] 30 68 }

  condition:
    any of them
}