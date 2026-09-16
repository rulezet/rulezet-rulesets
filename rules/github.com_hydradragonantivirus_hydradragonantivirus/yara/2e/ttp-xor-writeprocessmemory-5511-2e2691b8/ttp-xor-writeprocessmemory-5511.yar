rule TTP_XOR_WriteProcessMemory_5511 {
  strings:
    $key_5511 = { 02 63 [2] 30 41 [2] 36 74 [2] 18 74 [2] 27 68 }

  condition:
    any of them
}