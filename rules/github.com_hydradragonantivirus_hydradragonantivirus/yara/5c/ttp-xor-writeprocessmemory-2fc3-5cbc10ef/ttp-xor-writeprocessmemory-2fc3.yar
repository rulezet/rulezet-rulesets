rule TTP_XOR_WriteProcessMemory_2fc3 {
  strings:
    $key_2fc3 = { 78 b1 [2] 4a 93 [2] 4c a6 [2] 62 a6 [2] 5d ba }

  condition:
    any of them
}