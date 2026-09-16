rule TTP_XOR_WriteProcessMemory_3511 {
  strings:
    $key_3511 = { 62 63 [2] 50 41 [2] 56 74 [2] 78 74 [2] 47 68 }

  condition:
    any of them
}